package llmfs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dropsite-ai/llmfs/config"
)

var FilenameRegexp = regexp.MustCompile(`[^a-zA-Z0-9_\-]`)

func RowToFileRecord(row map[string]interface{}, currentUser string, includeContent bool) FileRecord {
	fr := FileRecord{
		ID:          AsInt64(row["id"]),
		Path:        AsString(row["path"]),
		IsDirectory: (AsInt64(row["is_directory"]) == 1),
		Description: AsString(row["description"]),
		CreatedAt:   ParseTime(row["created_at"]),
		UpdatedAt:   ParseTime(row["updated_at"]),
		BlobID:      AsInt64(row["blob_id"]),
	}
	if includeContent {
		fr.Content = AsString(row["content"])
	}
	if fr.BlobID != 0 {
		// Clear out the text content, if any
		fr.Content = ""

		// Generate ephemeral link valid for 10 minutes
		expires := time.Now().Add(10 * time.Minute)
		fr.BlobURL = GenerateSignedBlobURL(fr.BlobID, expires)
	}
	return fr
}

func GenerateSignedBlobURL(blobID int64, expires time.Time) string {
	secretKey := []byte(config.Cfg.JWTSecret)

	// Now only embed blobID + expiration in the HMAC
	base := fmt.Sprintf("%d|%d", blobID, expires.Unix())
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(base))
	sigHex := hex.EncodeToString(mac.Sum(nil))

	// Return a signed URL *without* any username param
	return fmt.Sprintf("/blobs/signed?blob_id=%d&exp=%d&sig=%s",
		blobID, expires.Unix(), sigHex)
}

func ParseTime(v interface{}) time.Time {
	s, ok := v.(string)
	if !ok || s == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		fmt.Printf("Warning: invalid time format for %q: %v\n", s, err)
		return time.Time{}
	}
	return t
}

func AsString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func AsInt64(v interface{}) int64 {
	switch val := v.(type) {
	case nil:
		return 0
	case int64:
		return val
	case int:
		return int64(val)
	case float64:
		return int64(val)
	case string:
		// Attempt to parse string as int64
		parsed, err := strconv.ParseInt(val, 10, 64)
		if err == nil {
			return parsed
		}
		fmt.Printf("Warning: could not parse string %q as int64: %v\n", val, err)
		return 0
	default:
		fmt.Printf("Warning: AsInt64 received an unexpected type: %T\n", v)
		return 0
	}
}

// fileIDPath holds (id, path) for matched records.
type fileIDPath struct {
	ID   int64
	Path string
}

func NilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// getParentDirectories returns all parent directories (from top down) for a given absolute file path.
// For example, for "/a/b/c.txt" it returns ["/a", "/a/b"].
// Now it always includes "/" even for paths like "/file.txt".
func getParentDirectories(path string) []string {
	var dirs []string

	// Remove trailing slash (except if the path is exactly "/")
	if path != "/" && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}

	// Always include the root directory.
	dirs = append(dirs, "/")

	// If the path is "/", we already have it.
	if path == "/" {
		return dirs
	}

	// Split the path into components.
	parts := strings.Split(path, "/")
	cum := ""
	// Start at index 1 (skip the empty element due to the leading "/")
	for i := 1; i < len(parts)-1; i++ {
		cum += "/" + parts[i]
		dirs = append(dirs, cum)
	}
	return dirs
}
