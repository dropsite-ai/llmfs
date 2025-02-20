package callbacks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/dropsite-ai/config"
	"github.com/dropsite-ai/llmfs"
	"github.com/dropsite-ai/llmfs/migrate"
	"github.com/dropsite-ai/sqliteutils/pool"
	"github.com/dropsite-ai/sqliteutils/test"
	"github.com/stretchr/testify/require"
)

// capturedRequest holds information about each callback invocation we receive in our mock server.
type capturedRequest struct {
	CallbackName string `json:"callback_name"`
	Timing       string `json:"timing"`
	Event        string `json:"event"`
	Path         string `json:"path"`
}

// TestPerformFilesystemOpsWithCallbacks verifies pre/post callbacks, multiple matches, and error handling.
func TestPerformFilesystemOpsWithCallbacks(t *testing.T) {
	ctx := context.Background()

	// 1) Spin up an in-memory SQLite database for testing:
	err := test.Pool(ctx, t, "", 1)
	require.NoError(t, err, "failed to init test DB pool")
	defer pool.ClosePool()
	migrate.Migrate(ctx)

	// 2) Start a local HTTP server to capture callback requests.
	var mu sync.Mutex
	var requests []capturedRequest // we’ll store details from each callback
	var forcePreError, forcePostError bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read JSON payload
		bodyBytes, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		// Parse into map or a dedicated struct
		var payload map[string]interface{}
		json.Unmarshal(bodyBytes, &payload)

		// Extract a few fields of interest for our test
		cbName, _ := payload["callback_name"].(string)
		timing, _ := payload["timing"].(string)
		eventName, _ := payload["event"].(string)

		// We'll store the path from payload["trigger"].(map[string]interface{})["path"], if it exists
		var path string
		if triggerMap, ok := payload["trigger"].(map[string]interface{}); ok {
			if p, ok2 := triggerMap["path"].(string); ok2 {
				path = p
			}
		}

		// Capture the request data
		req := capturedRequest{
			CallbackName: cbName,
			Timing:       timing,
			Event:        eventName,
			Path:         path,
		}
		mu.Lock()
		requests = append(requests, req)
		mu.Unlock()

		// Decide if we want to force an error. For demonstration, we do so if:
		// - timing is "pre" and forcePreError = true
		// - timing is "post" and forcePostError = true
		if (timing == "pre" && forcePreError) || (timing == "post" && forcePostError) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"error","message":"forced error from test server"}`))
			return
		}

		// Otherwise respond with "status":"ok"
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","message":"all good"}`))
	}))
	defer srv.Close()

	// 3) Override llmfs.Variables so that your callbacks can find the endpoint:
	llmfs.Variables = &config.Variables{
		Endpoints: map[string]string{
			"testEndpoint": srv.URL,
		},
		Secrets: map[string]string{"root": "root_secret_here"},
		Users:   map[string]string{},
		Paths:   map[string]string{},
	}

	// 4) Define multiple callback definitions in llmfs.Callbacks. Suppose we have:
	//    - "A_pre" and "B_pre" that match the same path & event => both triggered pre.
	//    - "A_post" and "B_post" that match the same path & event => both triggered post.
	llmfs.Callbacks = []config.CallbackDefinition{
		{
			Name:      "A_pre",
			Events:    []string{"write"},
			Timing:    "pre",
			Target:    config.CallbackTarget{Type: "file", Path: "/somefile.txt"},
			Endpoints: []string{"testEndpoint"},
		},
		{
			Name:      "B_pre",
			Events:    []string{"write"},
			Timing:    "pre",
			Target:    config.CallbackTarget{Type: "file", Path: "/somefile.txt"},
			Endpoints: []string{"testEndpoint"},
		},
		{
			Name:      "A_post",
			Events:    []string{"write"},
			Timing:    "post",
			Target:    config.CallbackTarget{Type: "file", Path: "/somefile.txt"},
			Endpoints: []string{"testEndpoint"},
		},
		{
			Name:      "B_post",
			Events:    []string{"write"},
			Timing:    "post",
			Target:    config.CallbackTarget{Type: "file", Path: "/somefile.txt"},
			Endpoints: []string{"testEndpoint"},
		},
	}

	// 5) Build a single filesystem operation that tries to "write" to /somefile.txt.
	//    This triggers the "write" event => both pre and post callbacks should match.
	ops := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Type: "file",
				Path: llmfs.PathCriteria{
					Exactly: "/somefile.txt",
				},
			},
			Operations: []llmfs.SubOperation{
				{
					Operation: "write",
					Content: &llmfs.ContentPayload{
						Content: "some data",
					},
				},
			},
		},
	}

	// ---------------------------------------
	// CASE 1: No forced error => all callbacks succeed
	// ---------------------------------------
	forcePreError, forcePostError = false, false
	requests = nil // reset

	results, err := PerformFilesystemOpsWithCallbacks(ctx, "alice", ops)
	require.NoError(t, err)
	require.Len(t, results, 1)

	// Check overall error
	opRes := results[0]
	require.Empty(t, opRes.OverallError, "No pre callback forced an error => transaction should succeed")

	// Check sub-op results
	require.Len(t, opRes.SubOpResults, 1)
	subRes := opRes.SubOpResults[0]
	require.Empty(t, subRes.Error, "No error from sub-op => everything fine")

	// Now verify we got 4 callbacks in the log
	// - 2 pre callbacks (A_pre, B_pre)
	// - 2 post callbacks (A_post, B_post)
	mu.Lock()
	require.Len(t, requests, 4)
	mu.Unlock()

	// We can check each request to see that "callback_name" is correct, etc.
	names := map[string]bool{}
	timings := map[string]int{}
	mu.Lock()
	for _, r := range requests {
		names[r.CallbackName] = true
		timings[r.Timing]++
		// Also confirm the path in "trigger.path" is "/somefile.txt"
		require.Equal(t, "/somefile.txt", r.Path)
		require.Equal(t, "write", r.Event)
	}
	mu.Unlock()

	// Expect A_pre, B_pre, A_post, B_post all present
	require.True(t, names["A_pre"], "A_pre callback missing")
	require.True(t, names["B_pre"], "B_pre callback missing")
	require.True(t, names["A_post"], "A_post callback missing")
	require.True(t, names["B_post"], "B_post callback missing")

	require.Equal(t, 2, timings["pre"], "expected 2 pre callbacks")
	require.Equal(t, 2, timings["post"], "expected 2 post callbacks")

	// ---------------------------------------
	// CASE 2: Force a PRE error => entire transaction must abort
	// ---------------------------------------
	forcePreError, forcePostError = true, false
	requests = nil

	results2, err2 := PerformFilesystemOpsWithCallbacks(ctx, "alice", ops)
	require.NoError(t, err2)
	require.Len(t, results2, 1)

	opRes2 := results2[0]
	// We expect an overallError because the pre callback failed => transaction aborted
	require.NotEmpty(t, opRes2.OverallError, "Pre callback error => must abort transaction")

	require.Len(t, opRes2.SubOpResults, 1)
	subRes2 := opRes2.SubOpResults[0]
	require.Contains(t, subRes2.Error, "Pre-callback", "the sub-op should show the failing callback in the error")

	mu.Lock()
	require.NotEmpty(t, requests, "We must have attempted some callbacks.")
	// But the transaction never ran => no post callbacks
	// We'll see only the pre callbacks in the request list (one or both might have fired).
	mu.Unlock()

	// ---------------------------------------
	// CASE 3: Force a POST error => transaction still succeeds
	// ---------------------------------------
	forcePreError, forcePostError = false, true
	requests = nil

	results3, err3 := PerformFilesystemOpsWithCallbacks(ctx, "alice", ops)
	require.NoError(t, err3)
	require.Len(t, results3, 1)

	opRes3 := results3[0]
	// Post callback error shouldn't abort => so we expect no overallError
	require.Empty(t, opRes3.OverallError, "Post callback error must not abort transaction")

	require.Len(t, opRes3.SubOpResults, 1)
	subRes3 := opRes3.SubOpResults[0]
	// The subOpResults should contain the post-callback error
	require.NotEmpty(t, subRes3.Error, "We forced a post error => it should appear in subOpResults")

	mu.Lock()
	require.Len(t, requests, 4, "2 pre callbacks + 2 post callbacks were triggered again")
	mu.Unlock()

	t.Log("Callbacks test completed successfully with pre/post error checks, multiple callbacks, etc.")
}
