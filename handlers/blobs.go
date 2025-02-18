package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/dropsite-ai/llmfs"
	"github.com/dropsite-ai/sqliteutils/exec"
)

// ------------------------------------------------------------------
// 1) Initiate Upload Handler
// ------------------------------------------------------------------

// InitiateUploadRequest is the JSON payload for starting a new upload.
type InitiateUploadRequest struct {
	Name      string `json:"name"`
	TotalSize int64  `json:"total_size"`
	MimeType  string `json:"mime_type"`
}

func InitiateBlobUploadHandler(w http.ResponseWriter, r *http.Request) {
	// Require an authenticated user.
	currentUser, ok := r.Context().Value(UsernameKey).(string)
	if !ok || currentUser == "" {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	// Decode the JSON body.
	var req InitiateUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.TotalSize <= 0 {
		http.Error(w, "Missing file name or invalid total_size", http.StatusBadRequest)
		return
	}
	if req.MimeType == "" {
		req.MimeType = "application/octet-stream"
	}

	// (Optional) Enforce a daily usage limit.
	var totalBytes int64
	usageQuery := `
		SELECT IFNULL(SUM(content_length), 0) AS total_bytes
		FROM blobs
		WHERE username = :uname
		  AND created_at >= DATETIME('now', '-1 day')
	`
	usageParams := map[string]interface{}{":uname": currentUser}
	err := exec.Exec(r.Context(), usageQuery, usageParams, func(_ int, row map[string]interface{}) {
		totalBytes = llmfs.AsInt64(row["total_bytes"])
	})
	if err != nil {
		http.Error(w, "DB error checking usage: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// For example, limit to 100 MB per day.
	if totalBytes+req.TotalSize > 100*1024*1024 {
		http.Error(w, "Upload limit exceeded", http.StatusForbidden)
		return
	}

	// Build extra columns.
	extraCols := map[string]interface{}{
		"mime_type":      req.MimeType,
		"username":       currentUser, // ownership is stored here
		"content_length": req.TotalSize,
		"name":           req.Name,
	}

	// Create a new blob row using a zeroblob.
	blobID, err := exec.CreateBlob(r.Context(), "blobs", "data", req.TotalSize, extraCols)
	if err != nil {
		http.Error(w, "Failed to create blob: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return JSON with blob ID and the upload URL for chunk uploads.
	resp := map[string]interface{}{
		"blob_id":    blobID,
		"upload_url": fmt.Sprintf("/blobs/chunk?blob_id=%d", blobID),
		"mime_type":  req.MimeType,
		"name":       req.Name,
		"total_size": req.TotalSize,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ------------------------------------------------------------------
// 2) Chunk Upload Handler
// ------------------------------------------------------------------

// UploadBlobChunkHandler writes a raw chunk of data into the blob.
// It expects query parameters "blob_id" and "offset".
func UploadBlobChunkHandler(w http.ResponseWriter, r *http.Request) {
	// Require an authenticated user.
	currentUser, ok := r.Context().Value(UsernameKey).(string)
	if !ok || currentUser == "" {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	// Parse blob_id and offset from the query.
	blobIDStr := r.URL.Query().Get("blob_id")
	offsetStr := r.URL.Query().Get("offset")
	if blobIDStr == "" || offsetStr == "" {
		http.Error(w, "Missing blob_id or offset", http.StatusBadRequest)
		return
	}
	blobID, err := strconv.ParseInt(blobIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid blob_id", http.StatusBadRequest)
		return
	}
	offset, err := strconv.ParseInt(offsetStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid offset", http.StatusBadRequest)
		return
	}

	// (Optional) Verify that the blob belongs to currentUser.
	var owner string
	query := "SELECT username FROM blobs WHERE id = :id LIMIT 1;"
	params := map[string]interface{}{":id": blobID}
	err = exec.Exec(r.Context(), query, params, func(_ int, row map[string]interface{}) {
		owner = llmfs.AsString(row["username"])
	})
	if err != nil {
		http.Error(w, "DB error verifying blob owner: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if owner == "" {
		http.Error(w, "Blob not found", http.StatusNotFound)
		return
	}
	if owner != currentUser {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Read the chunk data.
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read chunk data: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(data) == 0 {
		http.Error(w, "Empty chunk", http.StatusBadRequest)
		return
	}

	// Write the chunk using exec.WriteBlobChunk.
	err = exec.WriteBlobChunk(r.Context(), "blobs", "data", blobID, offset, data)
	if err != nil {
		http.Error(w, "Failed to write blob chunk: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"status":  "ok",
		"blob_id": blobID,
		"offset":  offset,
		"written": len(data),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ------------------------------------------------------------------
// 3) Signed Read Handler
// ------------------------------------------------------------------

// ValidateSignedBlob validates the signature query parameters and returns the blobID.
// It expects "blob_id", "exp" (expiration as Unix timestamp) and "sig" in the URL query.
func ValidateSignedBlob(r *http.Request) (int64, error) {
	secretKey := []byte(llmfs.Cfg.JWTSecret)
	q := r.URL.Query()

	blobIDStr := q.Get("blob_id")
	expStr := q.Get("exp")
	sigHex := q.Get("sig")

	if blobIDStr == "" || expStr == "" || sigHex == "" {
		return 0, fmt.Errorf("missing required query parameters")
	}

	blobID, err := strconv.ParseInt(blobIDStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid blob_id: %w", err)
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid exp: %w", err)
	}
	if time.Now().Unix() > exp {
		return 0, fmt.Errorf("link expired")
	}

	// Recompute the signature using the base string "blobID|exp".
	base := fmt.Sprintf("%d|%d", blobID, exp)
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(base))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(sigHex)) {
		return 0, fmt.Errorf("invalid signature")
	}
	return blobID, nil
}

// GetSignedBlobHandler streams a blob after verifying a signed URL.
// It also checks that the blob’s "username" matches the current user.
func GetSignedBlobHandler(w http.ResponseWriter, r *http.Request) {
	// Validate the signed URL.
	blobID, err := ValidateSignedBlob(r)
	if err != nil {
		http.Error(w, "Signature validation failed: "+err.Error(), http.StatusForbidden)
		return
	}

	// Require an authenticated user.
	currentUser, ok := r.Context().Value(UsernameKey).(string)
	if !ok || currentUser == "" {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	// Retrieve blob metadata (MIME type and owner) from the database.
	var mimeType, owner string
	metaQuery := "SELECT mime_type, username FROM blobs WHERE id = :id LIMIT 1;"
	metaParams := map[string]interface{}{":id": blobID}
	err = exec.Exec(r.Context(), metaQuery, metaParams, func(_ int, row map[string]interface{}) {
		mimeType = llmfs.AsString(row["mime_type"])
		owner = llmfs.AsString(row["username"])
	})
	if err != nil {
		http.Error(w, "DB error retrieving blob metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if owner == "" {
		http.Error(w, "Blob not found", http.StatusNotFound)
		return
	}
	if owner != currentUser {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", mimeType)

	// Optional: support query parameters "offset" and "length" for partial reads.
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	length, _ := strconv.ParseInt(r.URL.Query().Get("length"), 10, 64)
	if length <= 0 {
		length = -1 // read the entire blob from offset
	}

	// Stream the blob using exec.StreamReadBlob.
	_, err = exec.StreamReadBlob(r.Context(), "blobs", "data", blobID, offset, length, w)
	if err != nil {
		http.Error(w, "Failed to stream blob data: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
