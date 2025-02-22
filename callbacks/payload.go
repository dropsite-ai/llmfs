package callbacks

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dropsite-ai/config"
	t "github.com/dropsite-ai/llmfs/types"
)

// buildCallbackRequestBody constructs the JSON payload for the callback. If you want one payload
// per subOp, you can do so. If you want one payload per matched path, replicate accordingly.
// buildCallbackRequestBody constructs the JSON payload for exactly one callback.
// That way, each callback's Name appears in the payload.
func buildCallbackRequestBody(
	cb config.CallbackDefinition,
	match t.MatchCriteria,
	subOp t.SubOperation,
	opIndex, subIndex int,
	event, timing string,
	subOpRes *t.SubOperationResult,
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
func chosenPathString(match t.MatchCriteria) string {
	if match.Path.Exactly != "" {
		return match.Path.Exactly
	}
	// fallback:
	return fmt.Sprintf("(match:%+v)", match.Path)
}
