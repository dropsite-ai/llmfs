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

				// We have exactly 1 sub-op
				require.Len(t, topRes.SubOpResults, 1)
				subRes := topRes.SubOpResults[0]
				require.Empty(t, subRes.Error)

				require.Len(t, subRes.Results, 1)
				assert.Equal(t, "/topdir/file1.txt", subRes.Results[0].Path)
				assert.Empty(t, subRes.Results[0].Content, "List-only should not return content")
			},
		},
		{
			name: "Read only on file1",
			operations: []types.FilesystemOperation{
				{
					Match: types.MatchCriteria{
						Path: types.PathCriteria{Contains: "file1"},
						Type: "file",
					},
					Operations: []types.SubOperation{
						{Operation: "read"},
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
				assert.Equal(t, "hello world", subRes.Results[0].Content)
			},
		},
		{
			name: "List+Read on file1 => expect 2 sub-ops",
			operations: []types.FilesystemOperation{
				{
					Match: types.MatchCriteria{
						Path: types.PathCriteria{Contains: "file1"},
						Type: "file",
					},
					Operations: []types.SubOperation{
						{Operation: "list"},
						{Operation: "read"},
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []types.OperationResult) {
				require.Len(t, opsResults, 1)
				topRes := opsResults[0]
				require.Empty(t, topRes.OverallError)

				require.Len(t, topRes.SubOpResults, 2, "list + read => 2 sub-ops")

				listSub := topRes.SubOpResults[0]
				readSub := topRes.SubOpResults[1]
				require.Empty(t, listSub.Error)
				require.Empty(t, readSub.Error)

				require.Len(t, listSub.Results, 1, "list should return 1 matching file")
				require.Len(t, readSub.Results, 1, "read should return 1 matching file")
				assert.Empty(t, listSub.Results[0].Content, "list doesn't include content")
				assert.Equal(t, "hello world", readSub.Results[0].Content, "read does include content")
			},
		},
		{
			name: "Write (create) a new file under /topdir",
			operations: []types.FilesystemOperation{
				{
					Match: types.MatchCriteria{
						Type: "directory",
						Path: types.PathCriteria{
							Exactly: "/topdir",
						},
					},
					Operations: []types.SubOperation{
						{
							Operation:    "write",
							RelativePath: "newfile.txt",
							Description:  "Newly created file",
							Content: &types.ContentPayload{
								Content: "some new content",
							},
							Permissions: map[string]string{"bob": "r"},
						},
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

				assert.NotNil(t, subRes.Updated)
			},
		},
		{
			name: "Delete file1",
			operations: []types.FilesystemOperation{
				{
					Match: types.MatchCriteria{
						Path: types.PathCriteria{Contains: "file1"},
						Type: "file",
					},
					Operations: []types.SubOperation{
						{Operation: "delete"},
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

				assert.NotNil(t, subRes.Updated)
			},
		},
		{
			name: "Write + Delete in one operation (2 sub-ops)",
			operations: []types.FilesystemOperation{
				{
					Match: types.MatchCriteria{
						Path: types.PathCriteria{Contains: "topdir"},
						Type: "directory",
					},
					Operations: []types.SubOperation{
						{
							Operation:    "write",
							RelativePath: "tempfile.txt",
							Description:  "File created then quickly removed",
							Content: &types.ContentPayload{
								Content: "Some ephemeral content",
							},
						},
						{
							Operation: "delete",
						},
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []types.OperationResult) {
				require.Len(t, opsResults, 1)
				topRes := opsResults[0]
				require.Empty(t, topRes.OverallError)

				require.Len(t, topRes.SubOpResults, 2)
				writeSub := topRes.SubOpResults[0]
				delSub := topRes.SubOpResults[1]

				require.Empty(t, writeSub.Error)
				require.Empty(t, delSub.Error)

				assert.NotNil(t, writeSub.Updated)
				assert.NotNil(t, delSub.Updated)
			},
		},
		{
			name: "List + Write in one operation",
			operations: []types.FilesystemOperation{
				{
					Match: types.MatchCriteria{
						Path: types.PathCriteria{Contains: "topdir"},
						Type: "directory",
					},
					Operations: []types.SubOperation{
						{Operation: "list"},
						{
							Operation:    "write",
							RelativePath: "anotherfile.txt",
							Description:  "Example file created in the same op as List",
							Content: &types.ContentPayload{
								Content: "Hello from List+Write test",
							},
						},
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []types.OperationResult) {
				require.Len(t, opsResults, 1)
				topRes := opsResults[0]

				require.Empty(t, topRes.OverallError)

				require.Len(t, topRes.SubOpResults, 2)
				listSub := topRes.SubOpResults[0]
				writeSub := topRes.SubOpResults[1]

				require.Empty(t, listSub.Error)
				require.Empty(t, writeSub.Error)

				require.NotEmpty(t, listSub.Results, "List should return something")
				assert.Empty(t, listSub.Results[0].Content, "List doesn't include content")

				assert.NotNil(t, writeSub.Updated)
			},
		},
		{
			name: "List + Read + Delete in one operation",
			operations: []types.FilesystemOperation{
				{
					Match: types.MatchCriteria{
						Path: types.PathCriteria{Contains: "file1"},
						Type: "file",
					},
					Operations: []types.SubOperation{
						{Operation: "list"},
						{Operation: "read"},
						{Operation: "delete"},
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []types.OperationResult) {
				require.Len(t, opsResults, 1)
				topRes := opsResults[0]
				require.Empty(t, topRes.OverallError)

				require.Len(t, topRes.SubOpResults, 3)
				listSub := topRes.SubOpResults[0]
				readSub := topRes.SubOpResults[1]
				delSub := topRes.SubOpResults[2]

				require.Empty(t, listSub.Error)
				require.Empty(t, readSub.Error)
				require.Empty(t, delSub.Error)

				require.Len(t, listSub.Results, 1, "List sub-op should have 1 result for file1")
				require.Len(t, readSub.Results, 1, "Read sub-op should have 1 result for file1")
				assert.Empty(t, listSub.Results[0].Content, "the 'list' row is metadata only")
				assert.NotEmpty(t, readSub.Results[0].Content, "the 'read' row includes content")

				assert.NotNil(t, delSub.Updated)
			},
		},
		{
			name: "Pagination test: limit to 1 result per page",
			operations: []types.FilesystemOperation{
				{
					Match: types.MatchCriteria{
						Path: types.PathCriteria{Contains: "file"},
						Type: "file",
					},
					Operations: []types.SubOperation{
						{
							Operation:  "list",
							Pagination: &types.Pagination{Page: 1, Limit: 1},
							Sort:       &types.Sort{Field: "path", Direction: "asc"},
						},
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
				require.Len(t, subRes.Results, 1, "limit=1 => exactly 1 item returned")
			},
		},
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
