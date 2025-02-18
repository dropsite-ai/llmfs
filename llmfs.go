package llmfs

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/dropsite-ai/config"
	"github.com/dropsite-ai/sqliteutils/exec"
)

// Config is the application config loaded from YAML.
type Config struct {
	JWTSecret string `yaml:"jwt_secret"` // ends with "Secret" => auto-generate if empty
	OwnerUser string `yaml:"owner_user"` // ends with "User" => validated
	AuthURL   string `yaml:"auth_url"`   // ends with "URL" => validated
}

// Cfg is the global in-memory copy of the loaded config.
var Cfg Config

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
	SubOpIndex  int          `json:"sub_op_index"`
	Error       string       `json:"error,omitempty"`
	Results     []FileRecord `json:"results,omitempty"`
	WriteCount  int64        `json:"write_count,omitempty"`
	DeleteCount int64        `json:"delete_count,omitempty"`
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

// ------------------------------------------------------------------
// PerformFilesystemOperations
// ------------------------------------------------------------------

// PerformFilesystemOperations processes an array of FilesystemOperation items.
// Each item has a "match" + multiple sub-operations, all run in one transaction.
func PerformFilesystemOperations(
	ctx context.Context,
	currentUser string,
	ownerUser string,
	operations []FilesystemOperation,
) ([]OperationResult, error) {

	isOwner := (currentUser == ownerUser)
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
			subRes := SubOperationResult{SubOpIndex: j}

			// 1) find matching paths for this subOp (applies subOp pagination/sort)
			matched, err := findMatchingPaths(ctx, topOp.Match, subOp.Pagination, subOp.Sort)
			if err != nil {
				subRes.Error = fmt.Sprintf("failed to find matching paths: %v", err)
				opRes.SubOpResults[j] = subRes
				// Decide if we keep going or break. Here, let's just keep going to gather other sub-ops.
				continue
			}

			// 2) build the necessary queries
			q, p, buildErr := buildSubOperationQueries(
				ctx,
				subOp,
				topOp.Match,
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
			opType, _ := row["op_type"].(string)

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
				case "delete":
					if cnt, ok := row["cnt"].(int64); ok {
						subRes.DeleteCount += cnt
					}
				case "write":
					if cnt, ok := row["cnt"].(int64); ok {
						subRes.WriteCount += cnt
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
	match MatchCriteria,
	matched []fileIDPath,
	opIndex int,
	subOpIndex int,
	currentUser string,
	isOwner bool,
) ([]string, []map[string]interface{}, error) {

	// We'll gather queries/params across all relevant sub-tasks (like a "write" that also sets perms).
	var queries []string
	var params []map[string]interface{}

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
		return nil, nil, fmt.Errorf("unknown operation: %s", subOp.Operation)
	}

	// Check that user has permission for each matched path
	if !isOwner {
		if err := checkPermissionsForAll(ctx, currentUser, matched, requiredPerm); err != nil {
			return nil, nil, fmt.Errorf("%s permission check failed: %w", subOp.Operation, err)
		}
	}

	switch subOp.Operation {
	case "list":
		q, p := buildListOrReadQuery(matched, opIndex, subOpIndex /* includeContent= */, false)
		if q != "" {
			queries = append(queries, q)
			params = append(params, p)
		}

	case "read":
		q, p := buildListOrReadQuery(matched, opIndex, subOpIndex /* includeContent= */, true)
		if q != "" {
			queries = append(queries, q)
			params = append(params, p)
		}

	case "delete":
		dq, dp := buildDeleteQuery(matched, opIndex, subOpIndex)
		queries = append(queries, dq...)
		params = append(params, dp...)

	case "write":
		// Build the "write" queries
		wq, wp := buildWriteQuery(matched, match, subOp, opIndex, subOpIndex)
		queries = append(queries, wq...)
		params = append(params, wp...)
	}

	return queries, params, nil
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
func buildListOrReadQuery(matched []fileIDPath, opIndex, subOpIndex int, includeContent bool) (string, map[string]interface{}) {
	if len(matched) == 0 {
		return "", nil
	}
	placeholders := make([]string, len(matched))
	params := map[string]interface{}{
		":op_idx":     opIndex,
		":sub_op_idx": subOpIndex,
	}

	for i, m := range matched {
		ph := fmt.Sprintf(":id%d", i)
		placeholders[i] = ph
		params[ph] = m.ID
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

	return query, params
}

// ------------------------------------------------------------------
// Delete Queries
// ------------------------------------------------------------------

// buildDeleteQuery returns queries for deleting all matched rows (and then selecting changes()).
func buildDeleteQuery(matched []fileIDPath, opIndex, subOpIndex int) ([]string, []map[string]interface{}) {
	if len(matched) == 0 {
		return nil, nil
	}

	placeholders := make([]string, len(matched))
	idParams := map[string]interface{}{
		":op_idx":     opIndex,
		":sub_op_idx": subOpIndex,
	}
	for i, m := range matched {
		ph := fmt.Sprintf(":id%d", i)
		placeholders[i] = ph
		idParams[ph] = m.ID
	}
	idList := strings.Join(placeholders, ", ")

	delQuery := fmt.Sprintf(`
DELETE FROM filesystem
WHERE id IN (%s);
`, idList)

	// Then we select the count of changes
	changesQuery := `
SELECT :op_idx AS op_idx,
       :sub_op_idx AS sub_op_idx,
       'delete' AS op_type,
       changes() AS cnt;
`

	return []string{delQuery, changesQuery}, []map[string]interface{}{idParams, {
		":op_idx":     opIndex,
		":sub_op_idx": subOpIndex,
	}}
}

// ------------------------------------------------------------------
// Write Queries
// ------------------------------------------------------------------

// buildWriteQuery handles "write" sub-ops: creating/updating files or directories, plus setting permissions.
// Modified signature: pass in the original match criteria.
func buildWriteQuery(
	matched []fileIDPath,
	match MatchCriteria,
	subOp SubOperation,
	opIndex, subOpIndex int,
) ([]string, []map[string]interface{}) {
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

	// Determine the target path.
	// If match exactly is provided, use that as the base path.
	newPath := match.Path.Exactly
	// If a relative path is provided, append it.
	if subOp.RelativePath != "" {
		newPath = BuildNewPath(newPath, subOp.RelativePath)
	}

	isDir := 0
	if subOp.Type == "directory" {
		isDir = 1
	}

	// NEW: If no match was found, then treat this as a create operation.
	if len(matched) == 0 && newPath != "" {
		insertParams := map[string]interface{}{
			":path":    newPath,
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
SELECT :op_idx AS op_idx,
		 :sub_op_idx AS sub_op_idx,
		 'write' AS op_type,
		 changes() AS cnt;
`
		queries = append(queries, changesQ)
		paramsList = append(paramsList, map[string]interface{}{
			":op_idx":     opIndex,
			":sub_op_idx": subOpIndex,
		})

		// Optionally process permissions.
		if len(subOp.Permissions) > 0 {
			for user, level := range subOp.Permissions {
				if level == "" {
					rq, rp := buildRevokePermissionQuery(newPath, user, opIndex, subOpIndex)
					queries = append(queries, rq...)
					paramsList = append(paramsList, rp...)
				} else {
					gq, gp := buildGrantPermissionQuery(newPath, user, level, opIndex, subOpIndex)
					queries = append(queries, gq...)
					paramsList = append(paramsList, gp...)
				}
			}
		}
		return queries, paramsList
	}

	// Otherwise, if matches were found, follow the existing update logic.
	if subOp.RelativePath == "" {
		// Updating existing matched items.
		placeholders := make([]string, len(matched))
		updateParams := map[string]interface{}{
			":desc":       NilIfEmpty(subOp.Description),
			":cnt":        NilIfEmpty(contentStr),
			":blob_id":    blobID,
			":op_idx":     opIndex,
			":sub_op_idx": subOpIndex,
		}
		for i, m := range matched {
			ph := fmt.Sprintf(":id%d", i)
			placeholders[i] = ph
			updateParams[ph] = m.ID
		}
		idList := strings.Join(placeholders, ", ")
		updateQ := fmt.Sprintf(`
UPDATE filesystem
SET description = CASE WHEN :desc IS NOT NULL THEN :desc ELSE description END,
	content     = CASE WHEN :cnt IS NOT NULL THEN :cnt ELSE content END,
	blob_id     = CASE WHEN :blob_id IS NOT NULL THEN :blob_id ELSE blob_id END,
	updated_at  = CURRENT_TIMESTAMP
WHERE id IN (%s);
`, idList)
		changesQ := `
SELECT :op_idx AS op_idx,
		 :sub_op_idx AS sub_op_idx,
		 'write' AS op_type,
		 changes() AS cnt;
`
		queries = append(queries, updateQ, changesQ)
		paramsList = append(paramsList, updateParams, map[string]interface{}{
			":op_idx":     opIndex,
			":sub_op_idx": subOpIndex,
		})

		// Process permissions if provided.
		if len(subOp.Permissions) > 0 {
			for _, m := range matched {
				for user, level := range subOp.Permissions {
					if level == "" {
						rq, rp := buildRevokePermissionQuery(m.Path, user, opIndex, subOpIndex)
						queries = append(queries, rq...)
						paramsList = append(paramsList, rp...)
					} else {
						gq, gp := buildGrantPermissionQuery(m.Path, user, level, opIndex, subOpIndex)
						queries = append(queries, gq...)
						paramsList = append(paramsList, gp...)
					}
				}
			}
		}
	} else {
		// Creating a new file under each matched directory.
		for _, m := range matched {
			newChildPath := BuildNewPath(m.Path, subOp.RelativePath)
			insertParams := map[string]interface{}{
				":path":    newChildPath,
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
)
ON CONFLICT(path) DO UPDATE SET
	description = CASE WHEN :desc IS NOT NULL THEN :desc ELSE description END,
	content     = CASE WHEN :cnt IS NOT NULL THEN :cnt ELSE content END,
	blob_id     = CASE WHEN :blob_id IS NOT NULL THEN :blob_id ELSE blob_id END,
	updated_at  = CURRENT_TIMESTAMP;
`
			queries = append(queries, insertQ)
			paramsList = append(paramsList, insertParams)
			changesQ := `
SELECT :op_idx AS op_idx,
		 :sub_op_idx AS sub_op_idx,
		 'write' AS op_type,
		 changes() AS cnt;
`
			queries = append(queries, changesQ)
			paramsList = append(paramsList, map[string]interface{}{
				":op_idx":     opIndex,
				":sub_op_idx": subOpIndex,
			})
			if len(subOp.Permissions) > 0 {
				for user, level := range subOp.Permissions {
					if level == "" {
						rq, rp := buildRevokePermissionQuery(newChildPath, user, opIndex, subOpIndex)
						queries = append(queries, rq...)
						paramsList = append(paramsList, rp...)
					} else {
						gq, gp := buildGrantPermissionQuery(newChildPath, user, level, opIndex, subOpIndex)
						queries = append(queries, gq...)
						paramsList = append(paramsList, gp...)
					}
				}
			}
		}
	}
	return queries, paramsList
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

func LoadConfig(yamlPath string) {
	var err error

	// Define default config
	defaultCfg := Config{OwnerUser: "root"}

	// Load (or create) the YAML file using the new config library.
	Cfg, err = config.Load(yamlPath, defaultCfg)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
}
