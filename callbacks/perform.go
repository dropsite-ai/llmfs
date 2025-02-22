package callbacks

import (
	"context"
	"errors"
	"fmt"

	"github.com/dropsite-ai/llmfs/config"
	"github.com/dropsite-ai/llmfs/operations"
	t "github.com/dropsite-ai/llmfs/types"
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
	ops []t.FilesystemOperation,
) ([]t.OperationResult, error) {

	// Because the existing logic runs each top-level FilesystemOperation in one transaction,
	// we'll handle them individually in a loop, building final results.
	var finalResults []t.OperationResult

	for opIndex, fsOp := range ops {
		opResult := t.OperationResult{
			OperationIndex: opIndex,
		}
		opResult.SubOpResults = make([]t.SubOperationResult, len(fsOp.Operations))

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
		realResults, txErr := operations.PerformFilesystemOperations(ctx, currentUser, []t.FilesystemOperation{fsOp})
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
	fsOp t.FilesystemOperation,
	opIndex int,
	opResult *t.OperationResult,
) error {

	for subIndex, subOp := range fsOp.Operations {
		event := subOp.Operation
		matchingCbs := matchCallbacks(config.Callbacks, event, "pre", fsOp.Match)
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
	fsOp t.FilesystemOperation,
	opIndex int,
	opResult *t.OperationResult,
) {
	for subIndex, subOp := range fsOp.Operations {
		event := subOp.Operation
		matchingCbs := matchCallbacks(config.Callbacks, event, "post", fsOp.Match)
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
