package llmfs

import "time"

// SubOperation corresponds to one sub-operation within the "operations" array
// under each top-level FilesystemOperation in the new JSON schema.
type SubOperation struct {
	Operation    string            `json:"operation"`               // "list", "read", "delete", "write"
	RelativePath string            `json:"relative_path,omitempty"` // subpath (for directories) or override for a file
	Type         string            `json:"type,omitempty"`          // file type of the relative path (if specified)
	Description  string            `json:"description,omitempty"`   // for write
	Content      *ContentPayload   `json:"content,omitempty"`       // for write
	Permissions  map[string]string `json:"permissions,omitempty"`   // for write
	Pagination   *Pagination       `json:"pagination,omitempty"`    // for list or read
	Sort         *Sort             `json:"sort,omitempty"`          // for list or read
}

// FilesystemOperation is the top-level object for each array element
// in the new JSON schema. It has a "match" + an array of sub-operations.
type FilesystemOperation struct {
	Match      MatchCriteria  `json:"match"`
	Operations []SubOperation `json:"operations"`
}

// SubOperationResult captures the result of a single sub-operation (e.g., one item in "operations").
type SubOperationResult struct {
	SubOpIndex int          `json:"sub_op_index"`
	Name       string       `json:"name,omitempty"`
	Changes    int          `json:"changes,omitempty"`
	Updated    *FileUpdate  `json:"updated,omitempty"`
	Results    []FileRecord `json:"results,omitempty"`
	Error      string       `json:"error,omitempty"`
}

// OperationResult corresponds to the outcome of one top-level array element in the request.
// Since each item can contain multiple sub-operations, we store them in SubOpResults.
type OperationResult struct {
	OperationIndex int                  `json:"operation_index"`
	OverallError   string               `json:"error,omitempty"`
	SubOpResults   []SubOperationResult `json:"sub_op_results,omitempty"`
}

// MatchCriteria defines the criteria for matching filesystem items (unchanged from old schema).
type MatchCriteria struct {
	Path        PathCriteria        `json:"path,omitempty"`
	Description DescriptionCriteria `json:"description,omitempty"`
	Content     ContentCriteria     `json:"content,omitempty"`
	Type        string              `json:"type,omitempty"` // "file" or "directory"
}

// PathCriteria defines how we match paths.
type PathCriteria struct {
	Exactly    string `json:"exactly,omitempty"`
	Contains   string `json:"contains,omitempty"`
	BeginsWith string `json:"begins_with,omitempty"`
	EndsWith   string `json:"ends_with,omitempty"`
}

// DescriptionCriteria defines how we match on description.
type DescriptionCriteria struct {
	Contains string `json:"contains,omitempty"`
}

// ContentCriteria defines how we match file content (via FTS).
type ContentCriteria struct {
	Contains string `json:"contains,omitempty"`
}

// ContentPayload holds data for a write operation (append/prepend/content/url).
// You can extend it with "append", "prepend", etc. if desired; here we keep a simple version.
type ContentPayload struct {
	Content string `json:"content,omitempty"`
	URL     string `json:"url,omitempty"`
	// If you add "append"/"prepend", include them here.
}

// Pagination controls LIMIT/OFFSET for list/read.
type Pagination struct {
	Page  int `json:"page,omitempty"`  // 1-based
	Limit int `json:"limit,omitempty"` // max items per page
}

// Sort controls ORDER BY in queries for list/read.
type Sort struct {
	Field     string `json:"field,omitempty"`     // e.g. "path", "created_at", "updated_at"
	Direction string `json:"direction,omitempty"` // "asc" or "desc"
}

// FileRecord represents a single file or directory result from list/read queries.
type FileRecord struct {
	ID          int64     `json:"id"`
	Path        string    `json:"path"`
	IsDirectory bool      `json:"is_directory"`
	Description string    `json:"description,omitempty"`
	Content     string    `json:"content,omitempty"`
	BlobID      int64     `json:"blob_id,omitempty"`
	BlobURL     string    `json:"blob_url,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// FileUpdate represents a single file or directory that was created, updated, or deleted.
type FileUpdate struct {
	Name string `json:"name,omitempty"` // "create", "update", "delete"
	Type string `json:"type,omitempty"` // "file" or "directory"
	Path string `json:"path"`
}

// FileIDPath holds (id, path) for matched records.
type FileIDPath struct {
	ID   int64
	Path string
}
