package llmfs

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dropsite-ai/sqliteutils/exec"
)

type contextKey int

const (
	UsernameKey contextKey = iota
)

// FilesystemOperation represents an operation on the filesystem.
type FilesystemOperation struct {
	Match      MatchCriteria `json:"match"`
	Operations Operations    `json:"operations"`
	Pagination *Pagination   `json:"pagination,omitempty"`
	Sort       *Sort         `json:"sort,omitempty"`
}

// Operations defines the available filesystem operations.
type Operations struct {
	List   bool            `json:"list,omitempty"`
	Read   bool            `json:"read,omitempty"`
	Delete bool            `json:"delete,omitempty"`
	Write  *WriteOperation `json:"write,omitempty"`
}

// FilesystemOperation corresponds to one item in the JSON array.
// MatchCriteria defines the criteria for matching filesystem items.
type MatchCriteria struct {
	Path        PathCriteria        `json:"path,omitempty"`
	Description DescriptionCriteria `json:"description,omitempty"`
	Content     ContentCriteria     `json:"content,omitempty"`
	Type        string              `json:"type,omitempty"` // "file" or "directory"
}

// PathCriteria defines the matching rules for paths.
type PathCriteria struct {
	Exactly    string `json:"exactly,omitempty"`
	Contains   string `json:"contains,omitempty"`
	BeginsWith string `json:"begins_with,omitempty"`
	EndsWith   string `json:"ends_with,omitempty"`
}

// DescriptionCriteria defines the matching rules for descriptions.
type DescriptionCriteria struct {
	Contains string `json:"contains,omitempty"`
}

// ContentCriteria defines the matching rules for file content.
type ContentCriteria struct {
	Contains string `json:"contains,omitempty"`
}

// WriteOperation details how to write/update a file or create a new file under matched directories.
type WriteOperation struct {
	RelativePath string          `json:"relative_path,omitempty"`
	Description  string          `json:"description,omitempty"`
	Content      *ContentPayload `json:"content,omitempty"`
	// Key = username, Value = string containing any subset of "wrld"
	Permissions map[string]string `json:"permissions,omitempty"`
}

// ContentPayload can hold direct content or a URL to fetch from.
type ContentPayload struct {
	Content string `json:"content,omitempty"`
	URL     string `json:"url,omitempty"`
}

// Pagination helps with limiting results.
type Pagination struct {
	Page  int `json:"page,omitempty"`
	Limit int `json:"limit,omitempty"`
}

// Sort for controlling ORDER BY in queries.
type Sort struct {
	Field     string `json:"field,omitempty"`     // e.g. "path", "created_at", "updated_at"
	Direction string `json:"direction,omitempty"` // "asc", "desc"
}

// OperationResult stores the outcome of one FilesystemOperation.
type OperationResult struct {
	OperationIndex int    `json:"operation_index"`
	Error          string `json:"error,omitempty"`

	// For listing or reading, we include results.
	Results []FileRecord `json:"results,omitempty"`

	// Count of newly written or updated items.
	WriteCount int64 `json:"write_count,omitempty"`

	// Count of deleted items.
	DeleteCount int64 `json:"delete_count,omitempty"`
}

// FileRecord is returned for listing/reading.
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

// PerformFilesystemOperations runs the entire batch of filesystem operations in one transaction.
func PerformFilesystemOperations(ctx context.Context, currentUser string, ownerUser string, operations []FilesystemOperation) ([]OperationResult, error) {
	results := make([]OperationResult, 0, len(operations))

	// If current user == owner, skip permission checks
	isOwner := (currentUser == ownerUser)

	// Prepare slices to collect SQL statements and their params
	var queries []string
	var paramsList []map[string]interface{}

	for i, op := range operations {
		res := OperationResult{OperationIndex: i}

		// 1) Find matching paths
		matched, matchErr := findMatchingPaths(ctx, op)
		if matchErr != nil {
			res.Error = fmt.Sprintf("failed to match paths: %v", matchErr)
			results = append(results, res)
			continue
		}

		// 2) Build queries for this operation
		opQueries, opParams, err := buildOperationQueries(ctx, op, matched, i, isOwner, currentUser)
		if err != nil {
			res.Error = err.Error()
			results = append(results, res)
			continue
		}

		queries = append(queries, opQueries...)
		paramsList = append(paramsList, opParams...)

		// 3) Add this result placeholder
		results = append(results, res)
	}

	// 4) Execute everything in one transaction
	txErr := exec.ExecMultiTx(ctx, queries, paramsList, func(_ int, row map[string]interface{}) {
		opType, _ := row["op_type"].(string)
		opIdxVal, _ := row["op_idx"].(int64)
		opIdx := int(opIdxVal)

		if opIdx < 0 || opIdx >= len(results) {
			return
		}

		switch opType {
		case "list":
			rec := RowToFileRecord(row, currentUser, false)
			results[opIdx].Results = append(results[opIdx].Results, rec)
		case "read":
			rec := RowToFileRecord(row, currentUser, true)
			results[opIdx].Results = append(results[opIdx].Results, rec)
		case "delete":
			if cnt, ok := row["cnt"].(int64); ok {
				results[opIdx].DeleteCount = cnt
			}
		case "write":
			if cnt, ok := row["cnt"].(int64); ok {
				results[opIdx].WriteCount += cnt
			}
		}
	})
	if txErr != nil {
		fmt.Println("Transaction failed:", txErr)
		return results, txErr
	}
	return results, nil
}

// buildOperationQueries centralizes the logic for List, Read, Write, Delete, etc.
// It returns the queries and params for a single FilesystemOperation.
func buildOperationQueries(
	ctx context.Context,
	op FilesystemOperation,
	matched []fileIDPath,
	opIndex int,
	isOwner bool,
	currentUser string,
) (
	queries []string,
	params []map[string]interface{},
	err error,
) {
	// If matched is empty, there's nothing to build queries for
	if len(matched) == 0 {
		return nil, nil, nil
	}

	// Helper for permission checks
	checkPerm := func(required string) error {
		if isOwner {
			// Owner automatically has all perms
			return nil
		}
		return checkPermissionsForAll(ctx, currentUser, matched, required)
	}

	// 1) List
	if op.Operations.List {
		if err := checkPerm("l"); err != nil {
			return nil, nil, fmt.Errorf("list permission check failed: %w", err)
		}
		q, p := buildListOrReadQuery(matched, opIndex, false)
		if q != "" {
			queries = append(queries, q)
			params = append(params, p)
		}
	}

	// 2) Read
	if op.Operations.Read {
		if err := checkPerm("r"); err != nil {
			return nil, nil, fmt.Errorf("read permission check failed: %w", err)
		}
		q, p := buildListOrReadQuery(matched, opIndex, true)
		if q != "" {
			queries = append(queries, q)
			params = append(params, p)
		}
	}

	// 3) Write
	if op.Operations.Write != nil {
		writeOp := op.Operations.Write
		if err := checkPerm("w"); err != nil {
			return nil, nil, fmt.Errorf("write permission check failed: %w", err)
		}

		wq, wp := buildWriteQuery(matched, writeOp, opIndex)
		queries = append(queries, wq...)
		params = append(params, wp...)

		// If new permission grants or revokes were provided, handle them
		if len(writeOp.Permissions) > 0 {
			if writeOp.RelativePath == "" {
				// Updating existing matched files => apply changes to each matched path
				for _, m := range matched {
					for user, level := range writeOp.Permissions {
						var permQueries []string
						var permParams []map[string]interface{}

						if level == "" {
							// Revoke
							permQueries, permParams = buildRevokePermissionQuery(m.Path, user)
						} else {
							// Grant
							permQueries, permParams = buildGrantPermissionQuery(m.Path, user, level)
						}
						queries = append(queries, permQueries...)
						params = append(params, permParams...)
					}
				}
			} else {
				// Creating new file in each matched directory => apply permission changes to the newly created path
				for _, m := range matched {
					newPath := BuildNewPath(m.Path, writeOp.RelativePath)
					for user, level := range writeOp.Permissions {
						var permQueries []string
						var permParams []map[string]interface{}

						if level == "" {
							permQueries, permParams = buildRevokePermissionQuery(newPath, user)
						} else {
							permQueries, permParams = buildGrantPermissionQuery(newPath, user, level)
						}
						queries = append(queries, permQueries...)
						params = append(params, permParams...)
					}
				}
			}
		}
	}

	// 4) Delete
	if op.Operations.Delete {
		if err := checkPerm("d"); err != nil {
			return nil, nil, fmt.Errorf("delete permission check failed: %w", err)
		}
		dq, dp := buildDeleteQuery(matched, opIndex)
		queries = append(queries, dq...)
		params = append(params, dp...)
	}

	return queries, params, nil
}

// checkPermissionsForAll ensures the 'user' has the given 'required' permission
// on *every* path in 'matched'. If not, returns an error (like the old code).
func checkPermissionsForAll(ctx context.Context, user string, matched []fileIDPath, required string) error {
	// If caller code hasn't already checked for isOwner, do it here:
	// if user == ownerUser { return nil }

	for _, item := range matched {
		can, err := HasPermission(ctx, user, item.Path, required)
		if err != nil {
			return err
		}
		if !can {
			return fmt.Errorf("permission denied (%s) on %s", required, item.Path)
		}
	}
	return nil
}

// buildListOrReadQuery returns a SELECT statement for either "list" or "read" functionality.
// If includeContent is true, it includes the content column and sets op_type = "read".
// Otherwise, it excludes content and sets op_type = "list".
func buildListOrReadQuery(matched []fileIDPath, opIndex int, includeContent bool) (string, map[string]interface{}) {
	if len(matched) == 0 {
		return "", nil
	}

	// Build placeholder list and parameters for IDs.
	placeholders := make([]string, len(matched))
	params := make(map[string]interface{})
	for i, m := range matched {
		ph := fmt.Sprintf(":id%d", i)
		placeholders[i] = ph
		// Use the placeholder (including colon) as key.
		params[ph] = m.ID
	}
	idPlaceholderList := strings.Join(placeholders, ", ")

	queryType := "list"
	selectCols := "id, path, is_directory, description, created_at, updated_at"
	if includeContent {
		queryType = "read"
		selectCols += ", content"
	}

	query := `
SELECT :op_idx AS op_idx,
       :op_type AS op_type,
       ` + selectCols + `
FROM filesystem
WHERE id IN (` + idPlaceholderList + `);
`
	// Note: keys now include the colon.
	params[":op_idx"] = opIndex
	params[":op_type"] = queryType
	return query, params
}

// buildDeleteQuery returns a parameterized DELETE (and a following count query).
func buildDeleteQuery(matched []fileIDPath, opIndex int) ([]string, []map[string]interface{}) {
	if len(matched) == 0 {
		return nil, nil
	}

	placeholders := make([]string, len(matched))
	idParams := make(map[string]interface{})
	for i, m := range matched {
		ph := fmt.Sprintf(":id%d", i)
		placeholders[i] = ph
		idParams[ph] = m.ID
	}
	idPlaceholderList := strings.Join(placeholders, ", ")

	deleteQuery := `
DELETE FROM filesystem WHERE id IN (` + idPlaceholderList + `);
`
	selectChangesQuery := `
SELECT :op_idx AS op_idx, 'delete' AS op_type, changes() AS cnt;
`
	// Build parameter maps.
	params1 := idParams
	params2 := map[string]interface{}{":op_idx": opIndex}
	return []string{deleteQuery, selectChangesQuery}, []map[string]interface{}{params1, params2}
}

// buildWriteQuery returns parameterized queries for write operations.
func buildWriteQuery(matched []fileIDPath, w *WriteOperation, opIndex int) ([]string, []map[string]interface{}) {
	if w == nil {
		return nil, nil
	}

	var queries []string
	var paramsList []map[string]interface{}
	var blobID *int64 // pointer, to detect if we found a "blob" reference
	contentStr := ""

	if w.Content != nil {
		if w.Content.URL != "" && strings.HasPrefix(w.Content.URL, "llmfs://blob/") {
			// Parse out the ID
			idStr := strings.TrimPrefix(w.Content.URL, "llmfs://blob/")
			parsedID, err := strconv.ParseInt(idStr, 10, 64)
			if err == nil && parsedID > 0 {
				blobID = &parsedID
			}
		}
		if w.Content.Content != "" && blobID == nil {
			// fallback if not a blob URL
			contentStr = w.Content.Content
		}
	}

	// (A) Update existing matched items.
	if w.RelativePath == "" {
		if len(matched) == 0 {
			return nil, nil
		}
		placeholders := make([]string, len(matched))
		idParams := make(map[string]interface{})
		for i, m := range matched {
			ph := fmt.Sprintf(":id%d", i)
			placeholders[i] = ph
			idParams[ph] = m.ID
		}
		idPlaceholderList := strings.Join(placeholders, ", ")

		updateQuery := `
UPDATE filesystem
SET description = CASE WHEN :desc IS NOT NULL THEN :desc ELSE description END,
    content     = CASE WHEN :cnt  IS NOT NULL THEN :cnt  ELSE content END,
    blob_id     = CASE WHEN :blob_id IS NOT NULL THEN :blob_id ELSE blob_id END,
    updated_at  = CURRENT_TIMESTAMP
WHERE id IN (` + idPlaceholderList + `);
`
		countQuery := `
SELECT :op_idx AS op_idx, 'write' AS op_type, changes() AS cnt;
`

		idParams[":desc"] = NilIfEmpty(w.Description)
		idParams[":cnt"] = NilIfEmpty(contentStr)
		idParams[":blob_id"] = blobID
		idParams[":op_idx"] = opIndex
		queries = append(queries, updateQuery, countQuery)
		paramsList = append(paramsList, idParams, nil)
	} else {
		// (B) Create a new file under each matched directory.
		if len(matched) == 0 {
			return nil, nil
		}
		for _, m := range matched {
			newPath := BuildNewPath(m.Path, w.RelativePath)
			insertQuery := `
INSERT INTO filesystem (path, is_directory, description, content, blob_id, permissions, created_at, updated_at)
VALUES (:path, 0, :desc, :cnt, :blob_id, '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
`
			countQuery := `
SELECT :op_idx AS op_idx, 'write' AS op_type, changes() AS cnt;
`
			paramsIns := map[string]interface{}{
				":path":    newPath,
				":desc":    NilIfEmpty(w.Description),
				":cnt":     NilIfEmpty(contentStr),
				":blob_id": blobID,
			}
			paramsCount := map[string]interface{}{
				":op_idx": opIndex,
			}
			queries = append(queries, insertQuery, countQuery)
			paramsList = append(paramsList, paramsIns, paramsCount)
		}
	}
	return queries, paramsList
}

// buildGrantPermissionQuery returns a parameterized query for granting permissions.
func buildGrantPermissionQuery(path, username, level string) ([]string, []map[string]interface{}) {
	query := `
UPDATE filesystem
SET permissions = json_set(
    CASE 
         WHEN json_valid(permissions) THEN permissions 
         ELSE json_object() 
    END,
    :json_key, :json_val
),
updated_at = CURRENT_TIMESTAMP
WHERE path = :path;
`
	jsonKey := fmt.Sprintf("$.%s", username)
	params := map[string]interface{}{
		":json_key": jsonKey,
		":json_val": level,
		":path":     path,
	}
	return []string{query}, []map[string]interface{}{params}
}

// buildRevokePermissionQuery returns a parameterized query for revoking permissions.
func buildRevokePermissionQuery(path, username string) ([]string, []map[string]interface{}) {
	query := `
UPDATE filesystem
SET permissions = json_remove(
    CASE 
         WHEN json_valid(permissions) THEN permissions 
         ELSE json_object() 
    END,
    :json_key
),
updated_at = CURRENT_TIMESTAMP
WHERE path = :path;
`
	jsonKey := fmt.Sprintf("$.%s", username)
	params := map[string]interface{}{
		":json_key": jsonKey,
		":path":     path,
	}
	return []string{query}, []map[string]interface{}{params}
}

// findMatchingPaths now uses a parameterized subquery from buildMatchIntersectionQuery.
func findMatchingPaths(ctx context.Context, op FilesystemOperation) ([]fileIDPath, error) {
	// Build the subquery and its parameters.
	subquery, subParams := buildMatchIntersectionQuery(
		op.Match.Path.Exactly,
		op.Match.Path.Contains,
		op.Match.Path.BeginsWith,
		op.Match.Path.EndsWith,
		op.Match.Description.Contains,
		op.Match.Content.Contains,
	)
	if subquery == "" {
		return []fileIDPath{}, nil
	}

	var whereClauses []string

	// Filter by type.
	if op.Match.Type == "file" {
		whereClauses = append(whereClauses, "f.is_directory = 0")
	} else if op.Match.Type == "directory" {
		whereClauses = append(whereClauses, "f.is_directory = 1")
	}

	// Build ORDER BY.
	orderBy := ""
	if op.Sort != nil && op.Sort.Field != "" {
		dir := strings.ToLower(op.Sort.Direction)
		if dir != "desc" {
			dir = "asc"
		}
		switch op.Sort.Field {
		case "path", "created_at", "updated_at":
			orderBy = fmt.Sprintf("ORDER BY f.%s %s", op.Sort.Field, dir)
		default:
			orderBy = fmt.Sprintf("ORDER BY f.path %s", dir)
		}
	}

	// Pagination.
	limitOffset := ""
	if op.Pagination != nil && op.Pagination.Limit > 0 {
		page := op.Pagination.Page
		if page < 1 {
			page = 1
		}
		offset := (page - 1) * op.Pagination.Limit
		limitOffset = fmt.Sprintf("LIMIT %d OFFSET %d", op.Pagination.Limit, offset)
	}

	finalQuery := `
WITH matched_ids AS (
    ` + subquery + `
)
SELECT f.id, f.path
FROM filesystem f
INNER JOIN matched_ids m ON m.id = f.id
`
	if len(whereClauses) > 0 {
		finalQuery += "\nWHERE " + strings.Join(whereClauses, " AND ")
	}
	if orderBy != "" {
		finalQuery += "\n" + orderBy
	}
	if limitOffset != "" {
		finalQuery += "\n" + limitOffset
	}

	var matched []fileIDPath
	// Execute the final query with subParams.
	err := exec.Exec(ctx, finalQuery, subParams, func(_ int, row map[string]interface{}) {
		idVal, _ := row["id"].(int64)
		pathVal, _ := row["path"].(string)
		matched = append(matched, fileIDPath{
			ID:   idVal,
			Path: pathVal,
		})
	})
	if err != nil {
		return nil, err
	}
	return matched, nil
}

// BuildNewPath is a small helper to combine "parentDir" + "relativePath" with correct slashes.
func BuildNewPath(parentDir, rel string) string {
	p := strings.TrimSuffix(parentDir, "/")
	if p == "" {
		p = "/"
	}
	if p != "/" {
		p += "/"
	}
	return p + strings.TrimPrefix(rel, "/")
}

// EscapeSingleQuotes is a small helper for naive escaping inside string literals.
func EscapeSingleQuotes(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
