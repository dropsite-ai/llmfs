package callbacks

import (
	"github.com/dropsite-ai/config"
	t "github.com/dropsite-ai/llmfs/types"
)

// matchCallbacks filters the global callbacks (from config) to those that match:
//   - timing ("pre"/"post")
//   - event ("write","delete","read","list")
//   - target's type + path pattern (exactly, contains, etc.)
func matchCallbacks(
	all []config.CallbackDefinition,
	event string,
	timing string,
	match t.MatchCriteria,
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
		if !callbackPathMatches(t.PathCriteria{Exactly: cb.Target.Path}, match.Path) {
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
func callbackPathMatches(cbPath, opPath t.PathCriteria) bool {
	// If the callback has 'exactly' and it doesn't match the op's 'exactly', skip
	if cbPath.Exactly != "" && cbPath.Exactly != opPath.Exactly {
		return false
	}
	// Similarly for contains/begins/ends, etc.
	// (The idea is that the callback's path definition must be *at least* satisfied
	// by the operation’s path filter. If your system has more advanced matching, implement that here.)
	return true
}
