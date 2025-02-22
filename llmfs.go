package llmfs

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dropsite-ai/sqliteutils/exec"
)

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

// ------------------------------------------------------------------
// PerformFilesystemOperations
// ------------------------------------------------------------------

// PerformFilesystemOperations processes an array of FilesystemOperation items.
// Each item has a "match" + multiple sub-operations, all run in one transaction.
func PerformFilesystemOperations(
	ctx context.Context,
	currentUser string,
	operations []FilesystemOperation,
) ([]OperationResult, error) {

	isOwner := (currentUser == "root")
	results := make([]OperationResult, 0, len(operations))

	for i, topOp := range operations {
		opRes := OperationResult{
			OperationIndex: i,
			SubOpResults:   make([]SubOperationResult, len(topOp.Operations)),
		}

		// We gather all queries for all sub-ops, so they run in a single transaction for this top-level item.
		var allQueries []string
		var allParams []map[string]interface{}

		// For each sub-op, find matches (with sub-op pagination/sort if applicable),
		// build queries, and accumulate them.
		for j, subOp := range topOp.Operations {
			subRes := SubOperationResult{
				SubOpIndex: j,
				Name:       subOp.Operation,
			}

			// 1) find matching paths for this subOp (applies subOp pagination/sort)
			matched, err := findMatchingPaths(ctx, topOp.Match, subOp.Pagination, subOp.Sort)
			if err != nil {
				subRes.Error = fmt.Sprintf("failed to find matching paths: %v", err)
				opRes.SubOpResults[j] = subRes
				// Decide if we keep going or break. Here, let's just keep going to gather other sub-ops.
				continue
			}

			if len(matched) == 0 && subOp.Operation == "write" && topOp.Match.Path.Exactly != "" {
				matched = []fileIDPath{{ID: 0, Path: topOp.Match.Path.Exactly}}
			}

			// 2) build the necessary queries
			q, p, buildErr := buildSubOperationQueries(
				ctx,
				subOp,
				matched,
				i, // top-level operation index
				j, // sub-op index
				currentUser,
				isOwner,
			)
			if buildErr != nil {
				subRes.Error = buildErr.Error()
				opRes.SubOpResults[j] = subRes
				continue
			}

			// Accumulate them (note that we haven't run them yet).
			allQueries = append(allQueries, q...)
			allParams = append(allParams, p...)

			// Store partial results; final results (# of writes/deletes, fileRecords) will be
			// captured via callback below. For now, subRes might remain blank, we fill it after exec.
			opRes.SubOpResults[j] = subRes
		}

		// 3) Execute the accumulated queries in a single transaction.
		txErr := exec.ExecMultiTx(ctx, allQueries, allParams, func(_ int, row map[string]interface{}) {
			// The queries embed :op_idx and :sub_op_idx so we know where to route each row
			opIdxVal, _ := row["op_idx"].(int64)
			subOpIdxVal, _ := row["sub_op_idx"].(int64)
			subOpType, _ := row["sub_op_type"].(string)
			opType, _ := row["op_type"].(string)
			count, _ := row["cnt"].(int64)

			// Must check bounds
			if int(opIdxVal) == i && int(subOpIdxVal) >= 0 && int(subOpIdxVal) < len(opRes.SubOpResults) {
				subRes := &opRes.SubOpResults[subOpIdxVal]
				switch opType {
				case "list":
					fr := RowToFileRecord(row, currentUser, false)
					subRes.Results = append(subRes.Results, fr)
				case "read":
					fr := RowToFileRecord(row, currentUser, true)
					subRes.Results = append(subRes.Results, fr)
				case "create", "delete", "update":
					if updatedPath, ok := row["path"].(string); ok {
						subRes.Changes = int(count)
						subRes.Updated = &FileUpdate{
							Name: opType,
							Path: updatedPath,
							Type: subOpType,
						}
					}
				}
			}
		})
		if txErr != nil {
			// If the DB transaction itself failed, store the error at the top level.
			opRes.OverallError = txErr.Error()
		}

		results = append(results, opRes)
	}

	return results, nil
}

// ------------------------------------------------------------------
// Build queries for each sub-operation
// ------------------------------------------------------------------

// buildSubOperationQueries handles a single sub-op ("list", "read", "delete", "write").
// It does the permission checks, then calls the appropriate helper(s) to build queries.
func buildSubOperationQueries(
	ctx context.Context,
	subOp SubOperation,
	matched []fileIDPath,
	opIndex int,
	subOpIndex int,
	currentUser string,
	isOwner bool,
) ([]string, []map[string]interface{}, error) {
	// Decide required permission based on operation
	var requiredPerm string
	switch subOp.Operation {
	case "list":
		requiredPerm = "l"
	case "read":
		requiredPerm = "r"
	case "delete":
		requiredPerm = "d"
	case "write":
		requiredPerm = "w"
	default:
		return nil, nil, fmt.
			Errorf("unknown operation: %s", subOp.Operation)
	}

	finalMatched, err := expandPathsForSubOp(ctx, matched, subOp)
	if err != nil {
		return nil, nil, err
	}

	// Check that user has permission for each matched path
	if !isOwner {
		if err := checkPermissionsForAll(ctx, currentUser, finalMatched, requiredPerm); err != nil {
			return nil, nil, fmt.Errorf("%s permission check failed: %w", subOp.Operation, err)
		}
	}

	switch subOp.Operation {
	case "delete":
		return buildDeleteQuery(finalMatched, subOp, opIndex, subOpIndex)

	case "list":
		return buildListOrReadQuery(finalMatched, opIndex, subOpIndex, false)

	case "read":
		return buildListOrReadQuery(finalMatched, opIndex, subOpIndex, true)

	case "write":
		return buildWriteQuery(finalMatched, subOp, opIndex, subOpIndex)
	}

	return []string{}, []map[string]interface{}{}, nil
}

// checkPermissionsForAll ensures user has 'required' perms on *all* matched paths.
func checkPermissionsForAll(ctx context.Context, user string, matched []fileIDPath, required string) error {
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

// ------------------------------------------------------------------
// List/Read Queries
// ------------------------------------------------------------------

// buildListOrReadQuery returns a SELECT for either "list" (no content) or "read" (with content).
// We embed `:op_idx, :sub_op_idx, 'list'/'read' as op_type`.
func buildListOrReadQuery(paths []fileIDPath, opIndex, subOpIndex int, includeContent bool) ([]string, []map[string]interface{}, error) {
	if len(paths) == 0 {
		return nil, nil, nil
	}
	placeholders := make([]string, len(paths))
	params := map[string]interface{}{
		":op_idx":     opIndex,
		":sub_op_idx": subOpIndex,
	}

	for i, p := range paths {
		ph := fmt.Sprintf(":id%d", i)
		placeholders[i] = ph
		params[ph] = p.ID
	}
	idList := strings.Join(placeholders, ", ")

	opType := "list"
	selectCols := "id, path, is_directory, description, created_at, updated_at"
	if includeContent {
		opType = "read"
		selectCols += ", content, blob_id"
	}

	query := fmt.Sprintf(`
SELECT :op_idx AS op_idx,
       :sub_op_idx AS sub_op_idx,
       '%s' AS op_type,
       %s
FROM filesystem
WHERE id IN (%s);
`, opType, selectCols, idList)

	return []string{query}, []map[string]interface{}{params}, nil
}

// ------------------------------------------------------------------
// Delete Queries
// ------------------------------------------------------------------

// buildDeleteQuery returns queries for deleting all matched rows (and then selecting changes()).
func buildDeleteQuery(
	paths []fileIDPath,
	subOp SubOperation,
	opIndex, subOpIndex int,
) ([]string, []map[string]interface{}, error) {

	if len(paths) == 0 {
		return nil, nil, nil
	}

	var queries []string
	var paramsList []map[string]interface{}

	for _, p := range paths {
		delQ := `DELETE FROM filesystem WHERE id=:id;`
		delParams := map[string]interface{}{":id": p.ID}
		queries = append(queries, delQ)
		paramsList = append(paramsList, delParams)

		// Then capture changes() so we can see how many rows got deleted, etc.
		changesQ := `
SELECT :path AS path,
       :op_idx AS op_idx,
       :sub_op_idx AS sub_op_idx,
       :sub_opt_type AS sub_op_type,
       'delete' AS op_type,
       changes() AS cnt;`
		cParams := map[string]interface{}{
			":path":         p.Path,
			":op_idx":       opIndex,
			":sub_op_idx":   subOpIndex,
			":sub_opt_type": subOp.Type,
		}
		queries = append(queries, changesQ)
		paramsList = append(paramsList, cParams)
	}

	return queries, paramsList, nil
}

// ------------------------------------------------------------------
// Write Queries
// ------------------------------------------------------------------

// buildWriteQuery handles "write" sub-ops: creating/updating files or directories, plus setting permissions.
// Modified signature: pass in the original match criteria.
func buildWriteQuery(
	paths []fileIDPath, // fully expanded already
	subOp SubOperation,
	opIndex, subOpIndex int,
) ([]string, []map[string]interface{}, error) {
	var queries []string
	var paramsList []map[string]interface{}

	contentStr := ""
	var blobID *int64
	if subOp.Content != nil {
		if subOp.Content.URL != "" && strings.HasPrefix(subOp.Content.URL, "llmfs://blob/") {
			blobStr := strings.TrimPrefix(subOp.Content.URL, "llmfs://blob/")
			if parsed, err := strconv.ParseInt(blobStr, 10, 64); err == nil && parsed > 0 {
				blobID = &parsed
			}
		}
		if subOp.Content.Content != "" && blobID == nil {
			contentStr = subOp.Content.Content
		}
	}

	isDir := 0
	if subOp.Type == "directory" {
		isDir = 1
	}

	for _, p := range paths {
		if p.ID == 0 {
			insertParams := map[string]interface{}{
				":path":    p.Path,
				":dir":     isDir,
				":desc":    NilIfEmpty(subOp.Description),
				":cnt":     NilIfEmpty(contentStr),
				":blob_id": blobID,
			}
			insertQ := `
INSERT INTO filesystem (
	path, is_directory, description, content, blob_id, permissions,
	created_at, updated_at
)
VALUES (
	:path, :dir,
	CASE WHEN :desc IS NOT NULL THEN :desc ELSE '' END,
	CASE WHEN :cnt IS NOT NULL THEN :cnt ELSE '' END,
	:blob_id,
	'{}',
	CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
);
`
			queries = append(queries, insertQ)
			paramsList = append(paramsList, insertParams)

			changesQ := `
SELECT :path AS path, 
	:op_idx AS op_idx,
	:sub_op_idx AS sub_op_idx,
	:sub_opt_type AS sub_op_type,
	'create' AS op_type,
	changes() AS cnt;
`
			queries = append(queries, changesQ)
			paramsList = append(paramsList, map[string]interface{}{
				":path":         p.Path,
				":op_idx":       opIndex,
				":sub_op_idx":   subOpIndex,
				":sub_opt_type": subOp.Type,
			})
		} else {
			updateQ := `
UPDATE filesystem
SET description = CASE WHEN :desc IS NOT NULL THEN :desc ELSE description END,
    content     = CASE WHEN :cnt IS NOT NULL THEN :cnt ELSE content END,
    blob_id     = CASE WHEN :blob_id IS NOT NULL THEN :blob_id ELSE blob_id END,
    updated_at  = CURRENT_TIMESTAMP
WHERE path = :path;
`
			updateParams := map[string]interface{}{
				":path":       p.Path,
				":desc":       NilIfEmpty(subOp.Description),
				":cnt":        NilIfEmpty(contentStr),
				":blob_id":    blobID,
				":op_idx":     opIndex,
				":sub_op_idx": subOpIndex,
			}
			queries = append(queries, updateQ)
			paramsList = append(paramsList, updateParams)
			changesQ := `
SELECT :path AS path,
	:op_idx AS op_idx,
	:sub_op_idx AS sub_op_idx,
	:sub_opt_type AS sub_op_type,
	'update' AS op_type,
	changes() AS cnt;
`
			queries = append(queries, changesQ)
			paramsList = append(paramsList, map[string]interface{}{
				":path":         p.Path,
				":op_idx":       opIndex,
				":sub_op_idx":   subOpIndex,
				":sub_opt_type": subOp.Type,
			})
		}

		// Optionally process permissions.
		if len(subOp.Permissions) > 0 {
			for user, level := range subOp.Permissions {
				if level == "" {
					rq, rp := buildRevokePermissionQuery(p.Path, user, opIndex, subOpIndex)
					queries = append(queries, rq...)
					paramsList = append(paramsList, rp...)
				} else {
					gq, gp := buildGrantPermissionQuery(p.Path, user, level, opIndex, subOpIndex)
					queries = append(queries, gq...)
					paramsList = append(paramsList, gp...)
				}
			}
		}
	}

	return queries, paramsList, nil
}

// ------------------------------------------------------------------
// Permission Grant/Revoke Helper Queries
// ------------------------------------------------------------------

func buildGrantPermissionQuery(
	path, username, level string,
	opIndex, subOpIndex int,
) ([]string, []map[string]interface{}) {
	query := `
UPDATE filesystem
SET permissions = json_set(
    CASE WHEN json_valid(permissions) THEN permissions ELSE json_object() END,
    :json_key, :json_val
),
updated_at = CURRENT_TIMESTAMP
WHERE path = :path;
`
	params := map[string]interface{}{
		":json_key":   fmt.Sprintf("$.%s", username),
		":json_val":   level,
		":path":       path,
		":op_idx":     opIndex,
		":sub_op_idx": subOpIndex,
	}
	// We can do a SELECT changes() if needed, or not. For brevity, skip.
	return []string{query}, []map[string]interface{}{params}
}

func buildRevokePermissionQuery(
	path, username string,
	opIndex, subOpIndex int,
) ([]string, []map[string]interface{}) {
	query := `
UPDATE filesystem
SET permissions = json_remove(
    CASE WHEN json_valid(permissions) THEN permissions ELSE json_object() END,
    :json_key
),
updated_at = CURRENT_TIMESTAMP
WHERE path = :path;
`
	params := map[string]interface{}{
		":json_key":   fmt.Sprintf("$.%s", username),
		":path":       path,
		":op_idx":     opIndex,
		":sub_op_idx": subOpIndex,
	}
	return []string{query}, []map[string]interface{}{params}
}

// ------------------------------------------------------------------
// findMatchingPaths - Called once per subOp (with subOp pagination/sort).
// ------------------------------------------------------------------

// findMatchingPaths uses your existing FTS logic or direct path matching, then applies type checks.
// We updated it so it accepts subOp pagination/sort.
func findMatchingPaths(
	ctx context.Context,
	match MatchCriteria,
	pagination *Pagination,
	sort *Sort,
) ([]fileIDPath, error) {

	// 1) Build the subquery for path/desc/content FTS matches:
	subquery, subParams := buildMatchIntersectionQuery(
		match.Path.Exactly,
		match.Path.Contains,
		match.Path.BeginsWith,
		match.Path.EndsWith,
		match.Description.Contains,
		match.Content.Contains,
	)
	if subquery == "" {
		// No match constraints => likely return empty or everything. Let's return empty here.
		return []fileIDPath{}, nil
	}

	var whereClauses []string
	if match.Type == "file" {
		whereClauses = append(whereClauses, "f.is_directory = 0")
	} else if match.Type == "directory" {
		whereClauses = append(whereClauses, "f.is_directory = 1")
	}

	// 2) Sort
	orderBy := ""
	if sort != nil && sort.Field != "" {
		dir := strings.ToLower(sort.Direction)
		if dir != "desc" {
			dir = "asc"
		}
		switch sort.Field {
		case "path", "created_at", "updated_at":
			orderBy = fmt.Sprintf("ORDER BY f.%s %s", sort.Field, dir)
		default:
			// fallback
			orderBy = fmt.Sprintf("ORDER BY f.path %s", dir)
		}
	}

	// 3) Pagination
	limitOffset := ""
	if pagination != nil && pagination.Limit > 0 {
		page := pagination.Page
		if page < 1 {
			page = 1
		}
		offsetVal := (page - 1) * pagination.Limit
		limitOffset = fmt.Sprintf("LIMIT %d OFFSET %d", pagination.Limit, offsetVal)
	}

	// Build final query
	finalQuery := `
WITH matched_ids AS (
    ` + subquery + `
)
SELECT f.id, f.path
FROM filesystem f
JOIN matched_ids m ON m.id = f.id
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
	err := exec.Exec(ctx, finalQuery, subParams, func(_ int, row map[string]interface{}) {
		idVal, _ := row["id"].(int64)
		pathVal, _ := row["path"].(string)
		matched = append(matched, fileIDPath{ID: idVal, Path: pathVal})
	})
	if err != nil {
		return nil, err
	}

	// If "Exactly" was specified, but no row found, we might still allow a "non-existent" match
	// for creation logic. The old code did something like that.
	// Omitted here for brevity.

	return matched, nil
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

// BuildNewPath combines "parentDir" + "relativePath" with correct slashes.
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

// expandPathsForSubOp: given the subOp’s relative path and type, generate the actual (id, path) set
// you should operate on. If subOp.RelativePath is empty, it just returns `matched` as-is.
func expandPathsForSubOp(
	ctx context.Context,
	matched []fileIDPath,
	subOp SubOperation,
) ([]fileIDPath, error) {

	// If no relative path is given, we effectively operate on the matched set itself,
	// but we can still do a type-check filter if subOp.Type is specified.
	if subOp.RelativePath == "" {
		if subOp.Type == "" {
			return matched, nil
		}
		wantDir := (subOp.Type == "directory")
		filtered := make([]fileIDPath, 0, len(matched))
		for _, m := range matched {
			isDir, err := lookupIsDirectory(ctx, m.ID)
			if err != nil {
				return nil, err
			}
			if isDir == wantDir {
				filtered = append(filtered, m)
			}
		}
		return filtered, nil
	}

	// Otherwise, we have a relative path that we want to append to each matched item.
	// We'll see if it exists or not. If subOp.Operation == "write", we allow "nonexistent => create".
	finalPaths := make([]fileIDPath, 0, len(matched))
	wantDir := (subOp.Type == "directory")

	for _, m := range matched {
		childPath := BuildNewPath(m.Path, subOp.RelativePath)

		rowID, isDir, err := lookupPathIDAndDir(ctx, childPath)
		if err != nil {
			// Child doesn’t exist
			if subOp.Operation == "write" {
				// For a write, it’s valid to create it. Mark ID=0 => signals "INSERT".
				finalPaths = append(finalPaths, fileIDPath{ID: 0, Path: childPath})
				continue
			} else {
				// For list/read/delete, either skip or treat it as an error.
				return nil, fmt.Errorf("path '%s' not found (op=%s)", childPath, subOp.Operation)
			}
		}

		// If child *does* exist, confirm it’s the correct type (if subOp.Type is set).
		if subOp.Type != "" && isDir != wantDir {
			// Mismatch => skip or raise error. Example here: skip.
			continue
		}

		finalPaths = append(finalPaths, fileIDPath{ID: rowID, Path: childPath})
	}
	return finalPaths, nil
}

// lookupPathIDAndDir returns (id, isDirectory, error) or error if not found
func lookupPathIDAndDir(ctx context.Context, path string) (int64, bool, error) {
	query := `SELECT id, is_directory FROM filesystem WHERE path = :p LIMIT 1`
	params := map[string]interface{}{":p": path}

	var id int64
	var isDir bool
	var found bool
	err := exec.Exec(ctx, query, params, func(_ int, row map[string]interface{}) {
		id = AsInt64(row["id"])
		isDir = (AsInt64(row["is_directory"]) == 1)
		found = true
	})
	if err != nil {
		return 0, false, err
	}
	if !found {
		return 0, false, fmt.Errorf("no filesystem row for path=%s", path)
	}
	return id, isDir, nil
}

func lookupIsDirectory(ctx context.Context, id int64) (bool, error) {
	query := `SELECT is_directory FROM filesystem WHERE id = :id LIMIT 1;`
	params := map[string]interface{}{":id": id}

	var foundDir bool
	var found bool
	err := exec.Exec(ctx, query, params, func(_ int, row map[string]interface{}) {
		foundDir = (AsInt64(row["is_directory"]) == 1)
		found = true
	})
	if err != nil {
		return false, err
	}
	if !found {
		return false, fmt.Errorf("file id=%d not found", id)
	}
	return foundDir, nil
}
