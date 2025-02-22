package operations

import (
	"context"
	"fmt"
	"strings"

	"github.com/dropsite-ai/llmfs/fts"
	"github.com/dropsite-ai/llmfs/permissions"
	"github.com/dropsite-ai/llmfs/queries"
	t "github.com/dropsite-ai/llmfs/types"
	"github.com/dropsite-ai/llmfs/utils"
	"github.com/dropsite-ai/sqliteutils/exec"
)

// PerformFilesystemOperations processes an array of FilesystemOperation items.
// Each item has a "match" + multiple sub-operations, all run in one transaction.
func PerformFilesystemOperations(
	ctx context.Context,
	currentUser string,
	operations []t.FilesystemOperation,
) ([]t.OperationResult, error) {

	isOwner := (currentUser == "root")
	results := make([]t.OperationResult, 0, len(operations))

	for i, topOp := range operations {
		opRes := t.OperationResult{
			OperationIndex: i,
			SubOpResults:   make([]t.SubOperationResult, len(topOp.Operations)),
		}

		// We gather all queries for all sub-ops, so they run in a single transaction for this top-level item.
		var allQueries []string
		var allParams []map[string]interface{}

		// For each sub-op, find matches (with sub-op pagination/sort if applicable),
		// build queries, and accumulate them.
		for j, subOp := range topOp.Operations {
			subRes := t.SubOperationResult{
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
				matched = []t.FileIDPath{{ID: 0, Path: topOp.Match.Path.Exactly}}
			}

			// 2) build the necessary queries
			q, p, buildErr := BuildSubOperationQueries(
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
					fr := utils.RowToFileRecord(row, currentUser, false)
					subRes.Results = append(subRes.Results, fr)
				case "read":
					fr := utils.RowToFileRecord(row, currentUser, true)
					subRes.Results = append(subRes.Results, fr)
				case "create", "delete", "update":
					if updatedPath, ok := row["path"].(string); ok {
						subRes.Changes = int(count)
						subRes.Updated = &t.FileUpdate{
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

// BuildSubOperationQueries handles a single sub-op ("list", "read", "delete", "write").
// It does the permission checks, then calls the appropriate helper(s) to build queries.
func BuildSubOperationQueries(
	ctx context.Context,
	subOp t.SubOperation,
	matched []t.FileIDPath,
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
		if err := CheckPermissionsForAll(ctx, currentUser, finalMatched, requiredPerm); err != nil {
			return nil, nil, fmt.Errorf("%s permission check failed: %w", subOp.Operation, err)
		}
	}

	switch subOp.Operation {
	case "delete":
		return queries.BuildDeleteQuery(finalMatched, subOp, opIndex, subOpIndex)

	case "list":
		return queries.BuildListOrReadQuery(finalMatched, opIndex, subOpIndex, false)

	case "read":
		return queries.BuildListOrReadQuery(finalMatched, opIndex, subOpIndex, true)

	case "write":
		return queries.BuildWriteQuery(finalMatched, subOp, opIndex, subOpIndex)
	}

	return []string{}, []map[string]interface{}{}, nil
}

// findMatchingPaths uses your existing FTS logic or direct path matching, then applies type checks.
// We updated it so it accepts subOp pagination/sort.
func findMatchingPaths(
	ctx context.Context,
	match t.MatchCriteria,
	pagination *t.Pagination,
	sort *t.Sort,
) ([]t.FileIDPath, error) {

	// 1) Build the subquery for path/desc/content FTS matches:
	subquery, subParams := fts.BuildMatchIntersectionQuery(
		match.Path.Exactly,
		match.Path.Contains,
		match.Path.BeginsWith,
		match.Path.EndsWith,
		match.Description.Contains,
		match.Content.Contains,
	)
	if subquery == "" {
		// No match constraints => likely return empty or everything. Let's return empty here.
		return []t.FileIDPath{}, nil
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

	var matched []t.FileIDPath
	err := exec.Exec(ctx, finalQuery, subParams, func(_ int, row map[string]interface{}) {
		idVal, _ := row["id"].(int64)
		pathVal, _ := row["path"].(string)
		matched = append(matched, t.FileIDPath{ID: idVal, Path: pathVal})
	})
	if err != nil {
		return nil, err
	}

	// If "Exactly" was specified, but no row found, we might still allow a "non-existent" match
	// for creation logic. The old code did something like that.
	// Omitted here for brevity.

	return matched, nil
}

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
	matched []t.FileIDPath,
	subOp t.SubOperation,
) ([]t.FileIDPath, error) {

	// If no relative path is given, we effectively operate on the matched set itself,
	// but we can still do a type-check filter if subOp.Type is specified.
	if subOp.RelativePath == "" {
		if subOp.Type == "" {
			return matched, nil
		}
		wantDir := (subOp.Type == "directory")
		filtered := make([]t.FileIDPath, 0, len(matched))
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
	finalPaths := make([]t.FileIDPath, 0, len(matched))
	wantDir := (subOp.Type == "directory")

	for _, m := range matched {
		childPath := BuildNewPath(m.Path, subOp.RelativePath)

		rowID, isDir, err := lookupPathIDAndDir(ctx, childPath)
		if err != nil {
			// Child doesn’t exist
			if subOp.Operation == "write" {
				// For a write, it’s valid to create it. Mark ID=0 => signals "INSERT".
				finalPaths = append(finalPaths, t.FileIDPath{ID: 0, Path: childPath})
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

		finalPaths = append(finalPaths, t.FileIDPath{ID: rowID, Path: childPath})
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
		id = utils.AsInt64(row["id"])
		isDir = (utils.AsInt64(row["is_directory"]) == 1)
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
		foundDir = (utils.AsInt64(row["is_directory"]) == 1)
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

// CheckPermissionsForAll ensures user has 'required' perms on *all* matched paths.
func CheckPermissionsForAll(ctx context.Context, user string, matched []t.FileIDPath, required string) error {
	for _, item := range matched {
		can, err := permissions.HasPermission(ctx, user, item.Path, required)
		if err != nil {
			return err
		}
		if !can {
			return fmt.Errorf("permission denied (%s) on %s", required, item.Path)
		}
	}
	return nil
}
