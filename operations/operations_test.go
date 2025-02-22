package operations_test

import (
	"context"
	"testing"

	"github.com/dropsite-ai/llmfs/migrate"
	"github.com/dropsite-ai/llmfs/operations"
	"github.com/dropsite-ai/llmfs/types"
	"github.com/dropsite-ai/sqliteutils/exec"
	"github.com/dropsite-ai/sqliteutils/pool"
	"github.com/dropsite-ai/sqliteutils/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// initDatabase is a local helper for these tests:
func initDatabase(ctx context.Context, t *testing.T) {
	err := test.Pool(ctx, t, "", 1)
	require.NoError(t, err)
	migrate.Migrate(ctx)
}

// insertTestFile is a helper to add a row into the filesystem table for these tests.
func insertTestFile(t *testing.T, ctx context.Context,
	path string, isDirectory bool, description, content, permissions string,
) {
	query := `
    INSERT INTO filesystem (path, is_directory, description, content, permissions, created_at, updated_at)
    VALUES (:path, :is_directory, :desc, :content, :perm, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
    `
	isDirVal := 0
	if isDirectory {
		isDirVal = 1
	}
	params := map[string]interface{}{
		":path":         path,
		":is_directory": isDirVal,
		":desc":         description,
		":content":      content,
		":perm":         permissions,
	}
	err := exec.Exec(ctx, query, params, nil)
	require.NoError(t, err, "failed to insert test file record")
}

func TestPerformFilesystemOperations_Coverage(t *testing.T) {
	ctx := context.Background()

	// Table of scenarios to run
	tests := []struct {
		name       string
		operations []types.FilesystemOperation
		checkFn    func(t *testing.T, opsResults []types.OperationResult)
	}{
		{
			name: "List only on file1",
			operations: []types.FilesystemOperation{
				{
					Match: types.MatchCriteria{
						Path: types.PathCriteria{Contains: "file1"},
						Type: "file",
					},
					Operations: []types.SubOperation{
						{Operation: "list"},
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []types.OperationResult) {
				require.Len(t, opsResults, 1)
				topRes := opsResults[0]
				require.Empty(t, topRes.OverallError)

				require.Len(t, topRes.SubOpResults, 1)
				subRes := topRes.SubOpResults[0]
				require.Empty(t, subRes.Error)

				require.Len(t, subRes.Results, 1)
				assert.Equal(t, "/topdir/file1.txt", subRes.Results[0].Path)
				assert.Empty(t, subRes.Results[0].Content, "List-only should not return content")
			},
		},
		// ... other sub-tests from your table ...
	}

	// Run all subtests, each with a fresh DB
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			initDatabase(ctx, t)
			defer pool.ClosePool()

			// Insert baseline data
			insertTestFile(t, ctx, "/topdir", true, "Root directory", "", `{"alice":"wrld"}`)
			insertTestFile(t, ctx, "/topdir/file1.txt", false, "File #1", "hello world", `{"alice":"rld"}`)

			results, err := operations.PerformFilesystemOperations(ctx, "alice", tc.operations)
			require.NoError(t, err, "PerformFilesystemOperations should not error")

			tc.checkFn(t, results)
		})
	}
}

// TestNoMatches ensures we handle zero matches gracefully.
func TestNoMatches(t *testing.T) {
	ctx := context.Background()
	initDatabase(ctx, t)
	defer pool.ClosePool()

	// No inserted files => no matches
	input := []types.FilesystemOperation{
		{
			Match: types.MatchCriteria{
				Path: types.PathCriteria{Contains: "nonexistent.txt"},
			},
			Operations: []types.SubOperation{
				{Operation: "list"},
				{Operation: "read"},
				{Operation: "write"}, // won't happen
				{Operation: "delete"},
			},
		},
	}
	results, err := operations.PerformFilesystemOperations(ctx, "alice", input)
	require.NoError(t, err)

	require.Len(t, results, 1)
	topRes := results[0]
	assert.Empty(t, topRes.OverallError, "no error expected even with no matches")

	require.Len(t, topRes.SubOpResults, 4)
	for _, s := range topRes.SubOpResults {
		assert.Empty(t, s.Error)
		assert.Empty(t, s.Results)
		assert.Nil(t, s.Updated)
	}
}

// TestPermissionDenied checks that we reject read attempts from a user lacking 'r'.
func TestPermissionDenied(t *testing.T) {
	ctx := context.Background()
	initDatabase(ctx, t)
	defer pool.ClosePool()

	// Insert a file only "alice" can read
	insertTestFile(t, ctx, "/secretfile.txt", false, "Secret", "top secret content", `{"alice":"r"}`)

	// "bob" tries to read
	input := []types.FilesystemOperation{
		{
			Match: types.MatchCriteria{
				Path: types.PathCriteria{Contains: "secretfile"},
				Type: "file",
			},
			Operations: []types.SubOperation{
				{Operation: "read"},
			},
		},
	}
	results, err := operations.PerformFilesystemOperations(ctx, "bob", input)
	require.NoError(t, err)
	require.Len(t, results, 1)

	topRes := results[0]
	require.Empty(t, topRes.OverallError)

	require.Len(t, topRes.SubOpResults, 1)
	subRes := topRes.SubOpResults[0]
	assert.Contains(t, subRes.Error, "permission denied")
	assert.Empty(t, subRes.Results)
}

// TestGrantAndRevokeInSameOperation ensures one operation can both grant and revoke permissions.
func TestGrantAndRevokeInSameOperation(t *testing.T) {
	ctx := context.Background()
	initDatabase(ctx, t)
	defer pool.ClosePool()

	// Insert a file with existing perms
	insertTestFile(t, ctx, "/somefile.txt", false, "Some file", "Content", `{"alice":"wrld","charlie":"r"}`)

	// Revoke charlie, grant bob
	input := []types.FilesystemOperation{
		{
			Match: types.MatchCriteria{
				Path: types.PathCriteria{Contains: "somefile"},
				Type: "file",
			},
			Operations: []types.SubOperation{
				{
					Operation: "write",
					Permissions: map[string]string{
						"charlie": "",
						"bob":     "r",
					},
				},
			},
		},
	}
	results, err := operations.PerformFilesystemOperations(ctx, "alice", input)
	require.NoError(t, err)
	require.Len(t, results, 1)

	topRes := results[0]
	require.Empty(t, topRes.OverallError)
	require.Len(t, topRes.SubOpResults, 1)
	assert.Empty(t, topRes.SubOpResults[0].Error)

	// Confirm in DB
	var permString string
	query := `SELECT permissions FROM filesystem WHERE path = '/somefile.txt'`
	execErr := exec.Exec(ctx, query, nil, func(_ int, row map[string]interface{}) {
		permString, _ = row["permissions"].(string)
	})
	require.NoError(t, execErr)
	assert.Contains(t, permString, `"bob":"r"`)
	assert.NotContains(t, permString, "charlie")
}

// TestPaginationAndSorting demonstrates a multi-file scenario with a 2-item page limit.
func TestPaginationAndSorting(t *testing.T) {
	ctx := context.Background()
	initDatabase(ctx, t)
	defer pool.ClosePool()

	insertTestFile(t, ctx, "/fileA.txt", false, "Alpha", "", `{"alice":"l"}`)
	insertTestFile(t, ctx, "/fileB.txt", false, "Bravo", "", `{"alice":"l"}`)
	insertTestFile(t, ctx, "/fileC.txt", false, "Charlie", "", `{"alice":"l"}`)

	// Page 1 => sub-op with pagination
	input := []types.FilesystemOperation{
		{
			Match: types.MatchCriteria{
				Path: types.PathCriteria{Contains: "file"},
				Type: "file",
			},
			Operations: []types.SubOperation{
				{
					Operation:  "list",
					Pagination: &types.Pagination{Page: 1, Limit: 2},
					Sort:       &types.Sort{Field: "path", Direction: "asc"},
				},
			},
		},
	}
	results, err := operations.PerformFilesystemOperations(ctx, "alice", input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	topRes := results[0]
	require.Empty(t, topRes.OverallError)
	require.Len(t, topRes.SubOpResults, 1)

	page1Sub := topRes.SubOpResults[0]
	require.Empty(t, page1Sub.Error)
	require.Len(t, page1Sub.Results, 2, "limit=2 => only 2 items: fileA, fileB")

	// Page 2 => same match, but Page=2
	input2 := []types.FilesystemOperation{
		{
			Match: types.MatchCriteria{
				Path: types.PathCriteria{Contains: "file"},
				Type: "file",
			},
			Operations: []types.SubOperation{
				{
					Operation:  "list",
					Pagination: &types.Pagination{Page: 2, Limit: 2},
					Sort:       &types.Sort{Field: "path", Direction: "asc"},
				},
			},
		},
	}
	results2, err2 := operations.PerformFilesystemOperations(ctx, "alice", input2)
	require.NoError(t, err2)
	require.Len(t, results2, 1)
	topRes2 := results2[0]
	require.Empty(t, topRes2.OverallError)
	require.Len(t, topRes2.SubOpResults, 1)

	page2Sub := topRes2.SubOpResults[0]
	require.Empty(t, page2Sub.Error)
	require.Len(t, page2Sub.Results, 1, "Expect 1 leftover: fileC.txt")
}
