package llmfs_e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/dropsite-ai/llmfs"
	"github.com/dropsite-ai/llmfs/config"
	"github.com/golang-jwt/jwt" // or jwt/v4
	"github.com/stretchr/testify/require"
)

func TestEndToEndUserJourney(t *testing.T) {
	// Preliminary check: if the webserver is not up, skip tests.
	// Clear the cache: go clean -testcache
	resp, err := http.Get("http://localhost:8080/ok")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Skip("Webserver not up, skipping tests")
	}
	resp.Body.Close()

	config.Load("../llmfs.yaml")

	// Step 1: Generate a valid root token
	rootToken, err := generateJWT("root", config.Cfg.JWTSecret)
	require.NoError(t, err, "failed to generate root token")

	// We will pick a test username, and define a user secret
	const testUser = "testuser"
	const testUserSecret = "super_secret_for_testuser"

	//----------------------------------------------------------------------
	// Step 2: As root, create /llmfs/users/testuser.json with {"jwt_secret":"..."}
	//----------------------------------------------------------------------
	opsCreateUserFile := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Path: llmfs.PathCriteria{
					Exactly: fmt.Sprintf("/llmfs/users/%s.json", testUser),
				},
				Type: "file", // we’re effectively creating a file
			},
			Operations: []llmfs.SingleOperation{
				{
					Operation: "write",
					Content: &llmfs.ContentPayload{
						Content: fmt.Sprintf(`{"jwt_secret":%q}`, testUserSecret),
					},
				},
			},
		},
	}
	res := perform(t, rootToken, opsCreateUserFile)
	require.Len(t, res, 1)
	require.Empty(t, res[0].OverallError, "expected to successfully create /llmfs/users/testuser.json")

	//----------------------------------------------------------------------
	// Step 3: As root, create /users/testuser directory with wrld perms for testUser
	//----------------------------------------------------------------------
	opsCreateUserDir := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Path: llmfs.PathCriteria{
					Exactly: "/users",
				},
				Type: "directory",
			},
			Operations: []llmfs.SingleOperation{
				{
					Operation:    "write",
					RelativePath: testUser,    // creates "/users/testuser"
					Type:         "directory", // this ensures /users/testuser is written as a directory!
					Permissions:  map[string]string{testUser: "wrld"},
				},
			},
		},
	}
	res = perform(t, rootToken, opsCreateUserDir)
	require.Len(t, res, 1)
	require.Empty(t, res[0].OverallError, "expected to successfully create /users/testuser directory")

	//----------------------------------------------------------------------
	// Step 4: Generate a JWT token for testUser using their new secret
	//----------------------------------------------------------------------
	testUserToken, err := generateJWT(testUser, testUserSecret)
	require.NoError(t, err, "failed to generate testUser token")

	//----------------------------------------------------------------------
	// Step 5: Verify /auth works with testUser’s token
	//----------------------------------------------------------------------
	{
		resp := doGET(t, "http://localhost:8080/auth", testUserToken)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "testUser /auth should succeed")

		var authResp map[string]string
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&authResp))
		require.Equal(t, testUser, authResp["username"])
	}

	//----------------------------------------------------------------------
	// Step 6: Check testUser cannot read, list, or delete "/" or "/users"
	//----------------------------------------------------------------------
	opsBadPermissions := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Path: llmfs.PathCriteria{
					Exactly: "/",
				},
			},
			Operations: []llmfs.SingleOperation{
				{Operation: "list"},
			},
		},
	}
	res = perform(t, testUserToken, opsBadPermissions)
	require.Len(t, res, 1)
	require.Contains(t, res[0].SubOpResults[0].Error, "permission denied", "testUser should not have perms on /")

	opsBadPermissions[0].Match.Path.Exactly = "/users"
	res = perform(t, testUserToken, opsBadPermissions)
	require.Len(t, res, 1)
	require.Contains(t, res[0].SubOpResults[0].Error, "permission denied", "testUser should not have perms on /users")

	//----------------------------------------------------------------------
	// Step 7: Check testUser *can* read/list/write in "/users/testuser"
	//----------------------------------------------------------------------
	opsGoodPermissions := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Path: llmfs.PathCriteria{
					Exactly: fmt.Sprintf("/users/%s", testUser),
				},
				Type: "directory",
			},
			Operations: []llmfs.SingleOperation{
				{Operation: "list"},
			},
		},
	}
	res = perform(t, testUserToken, opsGoodPermissions)
	require.Len(t, res, 1)
	require.Empty(t, res[0].OverallError, "testUser should have no error listing their own directory")

	//----------------------------------------------------------------------
	// Step 8: Test writing a file in "/users/testuser"
	//----------------------------------------------------------------------
	opsWriteFile := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Path: llmfs.PathCriteria{
					Exactly: fmt.Sprintf("/users/%s", testUser),
				},
				Type: "directory",
			},
			Operations: []llmfs.SingleOperation{
				{
					Operation:    "write",
					RelativePath: "notes.txt",
					Content: &llmfs.ContentPayload{
						Content: "hello from testUser",
					},
				},
			},
		},
	}
	res = perform(t, testUserToken, opsWriteFile)
	require.Len(t, res, 1)
	require.Empty(t, res[0].OverallError, "testUser should be able to create a file under /users/testuser")

	uploadReq := map[string]interface{}{
		"name":       "test_blob.txt",
		"total_size": 4, // in bytes
		"mime_type":  "text/plain",
	}
	reqBody, err := json.Marshal(uploadReq)
	require.NoError(t, err, "failed to marshal blob upload request")

	blobResp := doPost(t, "http://localhost:8080/blobs", testUserToken, bytes.NewReader(reqBody), "application/json")
	defer blobResp.Body.Close()
	require.Equal(t, http.StatusOK, blobResp.StatusCode, "expected 200 OK from /blobs")

	var blobUploadResp map[string]interface{}
	require.NoError(t, json.NewDecoder(blobResp.Body).Decode(&blobUploadResp), "failed to decode /blobs response")
	blobIDFloat, ok := blobUploadResp["blob_id"].(float64)
	require.True(t, ok, "blob_id should be a number")
	blobID := int64(blobIDFloat)
	// (Optional) You could also check the provided upload_url.
	t.Logf("Initiated blob upload; blobID=%d", blobID)

	//----------------------------------------------------------------------
	// Step 10: Upload a chunk via POST /blobs/chunk.
	//----------------------------------------------------------------------
	chunkData := []byte("data") // 4 bytes of data
	chunkURL := fmt.Sprintf("http://localhost:8080/blobs/chunk?blob_id=%d&offset=0", blobID)
	chunkResp := doPost(t, chunkURL, testUserToken, bytes.NewReader(chunkData), "application/octet-stream")
	defer chunkResp.Body.Close()
	require.Equal(t, http.StatusOK, chunkResp.StatusCode, "expected 200 OK from /blobs/chunk")
	var chunkUploadResp map[string]interface{}
	require.NoError(t, json.NewDecoder(chunkResp.Body).Decode(&chunkUploadResp), "failed to decode /blobs/chunk response")
	require.Equal(t, "ok", chunkUploadResp["status"], "expected status 'ok' from /blobs/chunk")
	written, ok := chunkUploadResp["written"].(float64)
	require.True(t, ok, "written should be a number")
	require.Equal(t, 4, int(written), "expected 4 bytes written")

	//----------------------------------------------------------------------
	// Step 11: Download the blob using a signed URL via GET /blobs/signed.
	//----------------------------------------------------------------------
	// Use the helper in your code to generate a signed URL (which uses your JWT secret).
	expires := time.Now().Add(10 * time.Minute)
	signedPath := llmfs.GenerateSignedBlobURL(blobID, expires)
	signedURL := "http://localhost:8080" + signedPath

	signedResp := doGET(t, signedURL, testUserToken)
	defer signedResp.Body.Close()
	blobContent, err := io.ReadAll(signedResp.Body)
	require.Equal(t, http.StatusOK, signedResp.StatusCode, "expected 200 OK from /blobs/signed")
	require.NoError(t, err, "failed to read blob content")
	require.Equal(t, "data", string(blobContent), "downloaded blob content should match uploaded chunk")

	//----------------------------------------------------------------------
	// Step 12: Verify the /system endpoint returns the expected keys.
	//----------------------------------------------------------------------
	systemResp := doGET(t, "http://localhost:8080/system", testUserToken)
	defer systemResp.Body.Close()
	require.Equal(t, http.StatusOK, systemResp.StatusCode, "expected 200 OK from /system")
	var systemData map[string]interface{}
	require.NoError(t, json.NewDecoder(systemResp.Body).Decode(&systemData), "failed to decode /system response")
	require.Contains(t, systemData, "system_instruction", "/system response should contain system_instruction")
	require.Contains(t, systemData, "function_input_schema", "/system response should contain function_input_schema")
	require.Contains(t, systemData, "function_output_schema", "/system response should contain function_output_schema")

	//----------------------------------------------------------------------
	// All done!
	//----------------------------------------------------------------------
	t.Log("End-to-end user journey completed successfully.")
}

//----------------------------------------------------------------------------------
// Helper function to generate a short-lived JWT with the given username & secret
//----------------------------------------------------------------------------------

func generateJWT(username, secret string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(1 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

//----------------------------------------------------------------------------------
// A helper to call POST /perform with an array of llmfs.FilesystemOperation
// and parse back the []llmfs.OperationResult
//----------------------------------------------------------------------------------

func perform(t *testing.T, bearerToken string, ops []llmfs.FilesystemOperation) []llmfs.OperationResult {
	t.Helper()

	payload, err := json.Marshal(ops)
	require.NoError(t, err, "failed to marshal /perform payload")

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/perform", bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "POST /perform request failed")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "failed to read /perform response")

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"expected 200 from /perform, got %d", resp.StatusCode)

	var results []llmfs.OperationResult
	err = json.Unmarshal(body, &results)
	require.NoError(t, err, "failed to unmarshal JSON into []llmfs.OperationResult")

	return results
}

//----------------------------------------------------------------------------------
// A trivial GET helper with Bearer auth, to check /auth or any other GET endpoint
//----------------------------------------------------------------------------------

func doGET(t *testing.T, url, bearerToken string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err, "failed to construct GET request")

	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "GET request failed")
	return resp
}

//----------------------------------------------------------------------------------
// A trivial POST helper with Bearer auth, to check /blobs or any other POST endpoint
//----------------------------------------------------------------------------------

func doPost(t *testing.T, url, bearerToken string, body io.Reader, contentType string) *http.Response {
	req, err := http.NewRequest(http.MethodPost, url, body)
	require.NoError(t, err, "failed to construct POST request")
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "POST request failed")
	return resp
}
