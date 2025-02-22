package queries

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dropsite-ai/llmfs/permissions"
	t "github.com/dropsite-ai/llmfs/types"
)

// BuildListOrReadQuery returns a SELECT for either "list" (no content) or "read" (with content).
// We embed `:op_idx, :sub_op_idx, 'list'/'read' as op_type`.
func BuildListOrReadQuery(paths []t.FileIDPath, opIndex, subOpIndex int, includeContent bool) ([]string, []map[string]interface{}, error) {
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

// BuildDeleteQuery returns queries for deleting all matched rows (and then selecting changes()).
func BuildDeleteQuery(
	paths []t.FileIDPath,
	subOp t.SubOperation,
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

// buildWriteQuery handles "write" sub-ops: creating/updating files or directories, plus setting permissions.
// Modified signature: pass in the original match criteria.
func BuildWriteQuery(
	paths []t.FileIDPath, // fully expanded already
	subOp t.SubOperation,
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
					rq, rp := permissions.BuildRevokePermissionQuery(p.Path, user, opIndex, subOpIndex)
					queries = append(queries, rq...)
					paramsList = append(paramsList, rp...)
				} else {
					gq, gp := permissions.BuildGrantPermissionQuery(p.Path, user, level, opIndex, subOpIndex)
					queries = append(queries, gq...)
					paramsList = append(paramsList, gp...)
				}
			}
		}
	}

	return queries, paramsList, nil
}

func NilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
