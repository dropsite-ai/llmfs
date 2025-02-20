// callbacks/callbacks.go

package callbacks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dropsite-ai/config"
	"github.com/dropsite-ai/llmfs"
)

// PerformFilesystemOpsWithCallbacks is a wrapper around llmfs.PerformFilesystemOperations.
// It invokes "pre" callbacks before the DB transaction and "post" callbacks after it.
//
// The overall flow for each top-level operation:
//  1. For each sub-operation (each event), gather all "pre" callbacks whose event/target match.
//     Send POST requests to each callback's endpoints. If any fail, mark sub-op error & abort the
//     entire top-level operation's transaction.
//  2. If all "pre" callbacks succeed, proceed with the normal PerformFilesystemOperations logic for
//     that top-level item (one transaction).
//  3. After it commits, send "post" callbacks to all that apply. Any errors are logged and attached
//     to sub-op results but do not roll back the transaction.
func PerformFilesystemOpsWithCallbacks(
	ctx context.Context,
	currentUser string,
	operations []llmfs.FilesystemOperation,
) ([]llmfs.OperationResult, error) {

	// Because the existing logic runs each top-level FilesystemOperation in one transaction,
	// we'll handle them individually in a loop, building final results.
	var finalResults []llmfs.OperationResult

	for opIndex, fsOp := range operations {
		opResult := llmfs.OperationResult{
			OperationIndex: opIndex,
		}
		opResult.SubOpResults = make([]llmfs.SubOperationResult, len(fsOp.Operations))

		// -------------------------------------------------------
		// Step 1: Check "pre" callbacks for each subOp in this top-level operation
		// -------------------------------------------------------
		preErr := runPreCallbacksForOperation(fsOp, opIndex, &opResult)
		if preErr != nil {
			// If any pre callback fails => we abort this top-level operation's transaction.
			opResult.OverallError = preErr.Error()
			finalResults = append(finalResults, opResult)
			continue // skip the DB transaction for this operation
		}

		// -------------------------------------------------------
		// Step 2: Perform the actual filesystem operations in a transaction
		// -------------------------------------------------------
		realResults, txErr := llmfs.PerformFilesystemOperations(ctx, currentUser, []llmfs.FilesystemOperation{fsOp})
		if txErr != nil {
			opResult.OverallError = txErr.Error()
			finalResults = append(finalResults, opResult)
			continue
		}

		if len(realResults) == 1 {
			// Merge subOpResults from the real results
			opResult.SubOpResults = realResults[0].SubOpResults
			opResult.OverallError = realResults[0].OverallError
		}

		// -------------------------------------------------------
		// Step 3: Fire "post" callbacks for each subOp (only if the transaction succeeded).
		// -------------------------------------------------------
		runPostCallbacksForOperation(fsOp, opIndex, &opResult)

		finalResults = append(finalResults, opResult)
	}

	return finalResults, nil
}

// runPreCallbacksForOperation loops over each subOp, finds matching "pre" callbacks, and calls them.
// If any callback returns an error, we abort the entire top-level operation.
func runPreCallbacksForOperation(
	fsOp llmfs.FilesystemOperation,
	opIndex int,
	opResult *llmfs.OperationResult,
) error {

	for subIndex, subOp := range fsOp.Operations {
		event := subOp.Operation
		matchingCbs := matchCallbacks(llmfs.Callbacks, event, "pre", fsOp.Match)
		if len(matchingCbs) == 0 {
			continue
		}

		// Build + post a separate payload for each callback
		for _, cb := range matchingCbs {
			reqBody := buildCallbackRequestBody(
				cb, // pass the single callback
				fsOp.Match,
				subOp,
				opIndex, subIndex,
				event,
				"pre",
				nil, // no results for pre
			)
			// Now post
			if err := postToCallbackEndpoints(cb, reqBody); err != nil {
				opResult.SubOpResults[subIndex].Error =
					fmt.Sprintf("Pre-callback '%s' failed: %v", cb.Name, err)
				return errors.New(opResult.SubOpResults[subIndex].Error)
			}
		}
	}
	return nil
}

// runPostCallbacksForOperation loops over each subOp, finds matching "post" callbacks, and calls them.
// Errors are logged/stored but do NOT revert the transaction.
func runPostCallbacksForOperation(
	fsOp llmfs.FilesystemOperation,
	opIndex int,
	opResult *llmfs.OperationResult,
) {
	for subIndex, subOp := range fsOp.Operations {
		event := subOp.Operation
		matchingCbs := matchCallbacks(llmfs.Callbacks, event, "post", fsOp.Match)
		if len(matchingCbs) == 0 {
			continue
		}

		subOpRes := opResult.SubOpResults[subIndex]

		// Build + post separately for each callback
		for _, cb := range matchingCbs {
			reqBody := buildCallbackRequestBody(
				cb,
				fsOp.Match,
				subOp,
				opIndex, subIndex,
				event,
				"post",
				&subOpRes, // include results
			)
			if err := postToCallbackEndpoints(cb, reqBody); err != nil {
				errMsg := fmt.Sprintf("Post-callback '%s' error: %v", cb.Name, err)
				if subOpRes.Error == "" {
					subOpRes.Error = errMsg
				} else {
					subOpRes.Error += "; " + errMsg
				}
			}
		}

		// Persist any updated error info
		opResult.SubOpResults[subIndex] = subOpRes
	}
}

// matchCallbacks filters the global callbacks (from config) to those that match:
//   - timing ("pre"/"post")
//   - event ("write","delete","read","list")
//   - target's type + path pattern (exactly, contains, etc.)
func matchCallbacks(
	all []config.CallbackDefinition,
	event string,
	timing string,
	match llmfs.MatchCriteria,
) []config.CallbackDefinition {

	var filtered []config.CallbackDefinition
	for _, cb := range all {
		if cb.Timing != timing {
			continue
		}
		// Check event membership
		if !containsString(cb.Events, event) {
			continue
		}
		// Check target type: "file" or "directory"
		if cb.Target.Type != "" && cb.Target.Type != match.Type {
			continue
		}
		// Check path match – you can combine the same logic you use in findMatchingPaths.
		// For brevity, just do a quick utility here:
		if !callbackPathMatches(llmfs.PathCriteria{Exactly: cb.Target.Path}, match.Path) {
			continue
		}
		filtered = append(filtered, cb)
	}
	return filtered
}

func containsString(list []string, val string) bool {
	for _, s := range list {
		if s == val {
			return true
		}
	}
	return false
}

// callbackPathMatches checks if the callback's path criteria matches the operation's path filter.
// This is a simplified approach. Adjust to your exact specification as needed.
func callbackPathMatches(cbPath, opPath llmfs.PathCriteria) bool {
	// If the callback has 'exactly' and it doesn't match the op's 'exactly', skip
	if cbPath.Exactly != "" && cbPath.Exactly != opPath.Exactly {
		return false
	}
	// Similarly for contains/begins/ends, etc.
	// (The idea is that the callback's path definition must be *at least* satisfied
	// by the operation’s path filter. If your system has more advanced matching, implement that here.)
	return true
}

// buildCallbackRequestBody constructs the JSON payload for the callback. If you want one payload
// per subOp, you can do so. If you want one payload per matched path, replicate accordingly.
// buildCallbackRequestBody constructs the JSON payload for exactly one callback.
// That way, each callback's Name appears in the payload.
func buildCallbackRequestBody(
	cb config.CallbackDefinition,
	match llmfs.MatchCriteria,
	subOp llmfs.SubOperation,
	opIndex, subIndex int,
	event, timing string,
	subOpRes *llmfs.SubOperationResult,
) []byte {

	payload := map[string]interface{}{
		"callback_name": cb.Name, // <-- references the single callback
		"event":         event,
		"timing":        timing,
		"trigger": map[string]interface{}{
			"target_type": match.Type,
			"path":        chosenPathString(match),
		},
		"operation_details": map[string]interface{}{
			"operation_index": opIndex,
			"sub_op_index":    subIndex,
			"action":          subOp.Operation,
			"relative_path":   subOp.RelativePath,
			"description":     subOp.Description,
			"permissions":     subOp.Permissions, // map[string]string
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	// For post callbacks, attach subOp results
	if timing == "post" && subOpRes != nil {
		payload["results"] = subOpRes
	}

	data, _ := json.Marshal(payload)
	return data
}

// chosenPathString picks a representative path from the operation’s match criteria.
func chosenPathString(match llmfs.MatchCriteria) string {
	if match.Path.Exactly != "" {
		return match.Path.Exactly
	}
	// fallback:
	return fmt.Sprintf("(match:%+v)", match.Path)
}

// postToCallbackEndpoints sends the callback JSON to each endpoint defined in the callback’s .Endpoints array.
// If any fail for a PRE callback => we abort. For POST => we just record an error.
func postToCallbackEndpoints(cb config.CallbackDefinition, reqBody []byte) error {
	// Gather real URLs from the config:
	for _, endpointName := range cb.Endpoints {
		url, ok := llmfs.Variables.Endpoints[endpointName]
		if !ok || url == "" {
			return fmt.Errorf("callback '%s' references unknown endpoint '%s'", cb.Name, endpointName)
		}
		if err := doPost(url, reqBody); err != nil {
			return err
		}
	}
	return nil
}

// doPost is a simple helper to send the JSON body to a single endpoint
func doPost(url string, body []byte) error {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Expect a JSON response with "status":"ok" or "status":"error"
	var respBody struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	respBytes, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBytes, &respBody)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("callback endpoint returned status %d: %s", resp.StatusCode, string(respBytes))
	}
	if respBody.Status == "error" {
		return errors.New(respBody.Message)
	}
	return nil
}
