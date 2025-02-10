package llmfs_test

import (
	"context"
	"testing"
	"time"

	"github.com/dropsite-ai/llmfs"
	"github.com/dropsite-ai/llmfs/migrate"
	"github.com/dropsite-ai/sqliteutils/exec"
	"github.com/dropsite-ai/sqliteutils/pool"
	"github.com/dropsite-ai/sqliteutils/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func initDatabase(ctx context.Context, t *testing.T) {
	err := test.Pool(ctx, t, "", 1)
	require.NoError(t, err, "should create pool without error")
	migrate.Migrate(ctx)
}

// TestMigrateDatabase verifies that the migration runs and tables exist.
func TestMigrateDatabase(t *testing.T) {
	ctx := context.Background()

	initDatabase(ctx, t)
	defer func() {
		cerr := pool.ClosePool()
		assert.NoError(t, cerr, "closing pool should not fail")
	}()
}

// insertTestFile is a helper to add a row into the filesystem table.
func insertTestFile(t *testing.T, ctx context.Context,
	path string, isDirectory bool, description, content, permissions string,
) {
	query := `
INSERT INTO filesystem (path, is_directory, description, content, permissions, created_at, updated_at)
VALUES ($path, $is_directory, $desc, $content, $perm, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
`
	isDirVal := 0
	if isDirectory {
		isDirVal = 1
	}
	params := map[string]interface{}{
		"$path":         path,
		"$is_directory": isDirVal,
		"$desc":         description,
		"$content":      content,
		"$perm":         permissions,
	}
	err := exec.Exec(ctx, query, params, nil)
	require.NoError(t, err, "failed to insert test file record")
}

// TestHelperFunctions checks things like ParseTime, AsString, AsInt64, etc.
func TestHelperFunctions(t *testing.T) {
	t.Run("ParseTime valid", func(t *testing.T) {
		ts := llmfs.ParseTime("2023-01-02 15:04:05")
		require.Equal(t, 2023, ts.Year())
		require.Equal(t, time.January, ts.Month())
		require.Equal(t, 2, ts.Day())
		require.Equal(t, 15, ts.Hour())
	})

	t.Run("ParseTime empty", func(t *testing.T) {
		ts := llmfs.ParseTime("")
		require.True(t, ts.IsZero())
	})

	t.Run("AsString nil", func(t *testing.T) {
		require.Equal(t, "", llmfs.AsString(nil))
	})
	t.Run("AsString string", func(t *testing.T) {
		require.Equal(t, "hello", llmfs.AsString("hello"))
	})
	t.Run("AsString int64", func(t *testing.T) {
		require.Equal(t, "123", llmfs.AsString(int64(123)))
	})

	t.Run("AsInt64 nil", func(t *testing.T) {
		require.Equal(t, int64(0), llmfs.AsInt64(nil))
	})
	t.Run("AsInt64 int64", func(t *testing.T) {
		require.Equal(t, int64(999), llmfs.AsInt64(int64(999)))
	})

	t.Run("RowToFileRecord includes content", func(t *testing.T) {
		row := map[string]interface{}{
			"id":           int64(1),
			"path":         "/test.txt",
			"is_directory": int64(0),
			"description":  "test desc",
			"content":      "some content",
			"created_at":   "2023-01-01 10:00:00",
			"updated_at":   "2023-01-02 11:00:00",
		}
		fr := llmfs.RowToFileRecord(row, "alice", true)
		require.Equal(t, int64(1), fr.ID)
		require.Equal(t, "/test.txt", fr.Path)
		require.False(t, fr.IsDirectory)
		require.Equal(t, "test desc", fr.Description)
		require.Equal(t, "some content", fr.Content)
		require.Equal(t, 2023, fr.CreatedAt.Year())
		require.Equal(t, 2023, fr.UpdatedAt.Year())
	})

	t.Run("NilIfEmpty", func(t *testing.T) {
		require.Nil(t, llmfs.NilIfEmpty(""))
		require.Equal(t, "abc", llmfs.NilIfEmpty("abc"))
	})

	t.Run("BuildNewPath root", func(t *testing.T) {
		p := llmfs.BuildNewPath("/", "child.txt")
		require.Equal(t, "/child.txt", p)
	})
	t.Run("BuildNewPath subdir", func(t *testing.T) {
		p := llmfs.BuildNewPath("/some/dir", "child.txt")
		require.Equal(t, "/some/dir/child.txt", p)
	})

	t.Run("EscapeSingleQuotes", func(t *testing.T) {
		s := llmfs.EscapeSingleQuotes("John's doc")
		require.Equal(t, "John''s doc", s)
	})

	t.Run("ReverseString", func(t *testing.T) {
		r := llmfs.ReverseString("abc")
		require.Equal(t, "cba", r)
	})
}

// TestPerformFilesystemOperations_Coverage runs through a table of multi-op scenarios.
func TestPerformFilesystemOperations_Coverage(t *testing.T) {
	ctx := context.Background()

	// Table of scenarios
	tests := []struct {
		name       string
		operations []llmfs.FilesystemOperation
		checkFn    func(t *testing.T, opsResults []llmfs.OperationResult)
	}{
		{
			name: "List only on file1",
			operations: []llmfs.FilesystemOperation{
				{
					Match: llmfs.MatchCriteria{
						Path: llmfs.PathCriteria{Contains: "file1"},
						Type: "file",
					},
					Operations: llmfs.Operations{
						List: true,
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []llmfs.OperationResult) {
				require.Len(t, opsResults, 1)
				op := opsResults[0]
				require.Empty(t, op.Error)
				require.Len(t, op.Results, 1)
				assert.Equal(t, "/topdir/file1.txt", op.Results[0].Path)
				assert.Empty(t, op.Results[0].Content, "List-only should not return content")
			},
		},
		{
			name: "Read only on file1",
			operations: []llmfs.FilesystemOperation{
				{
					Match: llmfs.MatchCriteria{
						Path: llmfs.PathCriteria{Contains: "file1"},
						Type: "file",
					},
					Operations: llmfs.Operations{
						Read: true,
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []llmfs.OperationResult) {
				require.Len(t, opsResults, 1)
				op := opsResults[0]
				require.Empty(t, op.Error)
				require.Len(t, op.Results, 1)
				assert.Equal(t, "hello world", op.Results[0].Content)
			},
		},
		{
			name: "List+Read on file1 => expect 2 results",
			operations: []llmfs.FilesystemOperation{
				{
					Match: llmfs.MatchCriteria{
						Path: llmfs.PathCriteria{Contains: "file1"},
						Type: "file",
					},
					Operations: llmfs.Operations{
						List: true,
						Read: true,
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []llmfs.OperationResult) {
				require.Len(t, opsResults, 1)
				op := opsResults[0]
				require.Empty(t, op.Error)
				require.Len(t, op.Results, 2, "list + read yields two rows for the same file")
				assert.Empty(t, op.Results[0].Content, "first row is from 'list'")
				assert.Equal(t, "hello world", op.Results[1].Content, "second row is from 'read'")
			},
		},
		{
			name: "Write (create) a new file under /topdir",
			operations: []llmfs.FilesystemOperation{
				{
					Match: llmfs.MatchCriteria{
						Type: "directory",
						Path: llmfs.PathCriteria{
							Exactly: "/topdir",
						},
					},
					Operations: llmfs.Operations{
						Write: &llmfs.WriteOperation{
							RelativePath: "newfile.txt",
							Description:  "Newly created file",
							Content: &llmfs.ContentPayload{
								Content: "some new content",
							},
							Permissions: map[string]string{"bob": "r"}, // Example permission
						},
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []llmfs.OperationResult) {
				require.Len(t, opsResults, 1)
				op := opsResults[0]
				require.Empty(t, op.Error)
				assert.Equal(t, int64(1), op.WriteCount, "should have created exactly 1 file")
			},
		},
		{
			name: "Delete file1",
			operations: []llmfs.FilesystemOperation{
				{
					Match: llmfs.MatchCriteria{
						Path: llmfs.PathCriteria{Contains: "file1"},
						Type: "file",
					},
					Operations: llmfs.Operations{
						Delete: true,
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []llmfs.OperationResult) {
				require.Len(t, opsResults, 1)
				op := opsResults[0]
				require.Empty(t, op.Error)
				assert.Equal(t, int64(1), op.DeleteCount, "should delete exactly 1 file")
			},
		},
		{
			name: "Write + Delete in one operation",
			operations: []llmfs.FilesystemOperation{
				{
					Match: llmfs.MatchCriteria{
						Path: llmfs.PathCriteria{Contains: "topdir"},
						Type: "directory",
					},
					Operations: llmfs.Operations{
						Write: &llmfs.WriteOperation{
							RelativePath: "tempfile.txt",
							Description:  "File created then quickly removed",
							Content: &llmfs.ContentPayload{
								Content: "Some ephemeral content",
							},
						},
						Delete: true,
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []llmfs.OperationResult) {
				require.Len(t, opsResults, 1)
				op := opsResults[0]
				require.Empty(t, op.Error)
				assert.Equal(t, int64(1), op.WriteCount, "expected 1 new file")
				assert.True(t, op.DeleteCount >= 1, "expect at least 1 item to be deleted")
			},
		},
		{
			name: "List + Write in one operation",
			operations: []llmfs.FilesystemOperation{
				{
					Match: llmfs.MatchCriteria{
						Path: llmfs.PathCriteria{Contains: "topdir"},
						Type: "directory",
					},
					Operations: llmfs.Operations{
						List: true,
						Write: &llmfs.WriteOperation{
							RelativePath: "anotherfile.txt",
							Description:  "Example file created in the same op as List",
							Content: &llmfs.ContentPayload{
								Content: "Hello from List+Write test",
							},
						},
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []llmfs.OperationResult) {
				require.Len(t, opsResults, 1)
				op := opsResults[0]
				require.Empty(t, op.Error)

				require.NotEmpty(t, op.Results, "List should return something")
				assert.Empty(t, op.Results[0].Content, "List doesn't include content")

				assert.Equal(t, int64(1), op.WriteCount, "one file created")
			},
		},
		{
			name: "List + Read + Delete in one operation",
			operations: []llmfs.FilesystemOperation{
				{
					Match: llmfs.MatchCriteria{
						Path: llmfs.PathCriteria{Contains: "file1"},
						Type: "file",
					},
					Operations: llmfs.Operations{
						List:   true,
						Read:   true,
						Delete: true,
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []llmfs.OperationResult) {
				require.Len(t, opsResults, 1)
				op := opsResults[0]
				require.Empty(t, op.Error)

				require.Len(t, op.Results, 2, "List + Read produce 2 rows for the same file")
				assert.Empty(t, op.Results[0].Content, "the first row is list info only")
				assert.NotEmpty(t, op.Results[1].Content, "the second row is read content")
				assert.Equal(t, int64(1), op.DeleteCount, "deleted exactly 1 file")
			},
		},
		// (We exclude "No matches scenario" and "Grant+Revoke" from here
		//  because we have dedicated tests for those below.)
		{
			name: "Pagination test: limit to 1 result per page",
			operations: []llmfs.FilesystemOperation{
				{
					Match: llmfs.MatchCriteria{
						Path: llmfs.PathCriteria{Contains: "file"},
						Type: "file",
					},
					Pagination: &llmfs.Pagination{
						Page:  1,
						Limit: 1,
					},
					Sort: &llmfs.Sort{
						Field:     "path",
						Direction: "asc",
					},
					Operations: llmfs.Operations{
						List: true,
					},
				},
			},
			checkFn: func(t *testing.T, opsResults []llmfs.OperationResult) {
				require.Len(t, opsResults, 1)
				op := opsResults[0]
				require.Empty(t, op.Error)
				require.Len(t, op.Results, 1, "limit=1 => exactly 1 item returned")
			},
		},
	}

	// Run all subtests, each with a fresh DB
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			initDatabase(ctx, t)
			defer pool.ClosePool()

			// Insert baseline data for each scenario
			insertTestFile(t, ctx, "/topdir", true, "Root directory", "", `{"alice":"wrld"}`)
			insertTestFile(t, ctx, "/topdir/file1.txt", false, "File #1", "hello world", `{"alice":"rld"}`)

			results, err := llmfs.PerformFilesystemOperations(ctx, "alice", "owner", tc.operations)
			require.NoError(t, err, "PerformFilesystemOperations should not error")

			tc.checkFn(t, results)
		})
	}
}

// Below are additional dedicated tests for specific edge cases:

// TestNoMatches ensures we handle zero matches gracefully.
func TestNoMatches(t *testing.T) {
	ctx := context.Background()

	initDatabase(ctx, t)
	defer pool.ClosePool()

	// We do NOT insert any files, so definitely no matches
	input := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Path: llmfs.PathCriteria{Contains: "nonexistent.txt"},
			},
			Operations: llmfs.Operations{
				List:   true,
				Read:   true,
				Write:  &llmfs.WriteOperation{Description: "won't happen"},
				Delete: true,
			},
		},
	}
	results, err := llmfs.PerformFilesystemOperations(ctx, "alice", "owner", input)
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Empty(t, results[0].Error, "no error expected even with no matches")
	assert.Empty(t, results[0].Results, "no matched items")
	assert.Equal(t, int64(0), results[0].DeleteCount)
	assert.Equal(t, int64(0), results[0].WriteCount)
}

// TestPermissionDenied checks that we reject read attempts from a user lacking 'r'.
func TestPermissionDenied(t *testing.T) {
	ctx := context.Background()

	initDatabase(ctx, t)
	defer pool.ClosePool()

	// Insert a file only "alice" can read
	insertTestFile(t, ctx, "/secretfile.txt", false, "Secret", "top secret content", `{"alice":"r"}`)

	// "bob" tries to read
	input := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Path: llmfs.PathCriteria{Contains: "secretfile"},
				Type: "file",
			},
			Operations: llmfs.Operations{
				Read: true,
			},
		},
	}
	results, err := llmfs.PerformFilesystemOperations(ctx, "bob", "owner", input)
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Contains(t, results[0].Error, "permission denied")
	assert.Empty(t, results[0].Results)
}

// TestGrantAndRevokeInSameOperation ensures one operation can both grant and revoke permissions.
func TestGrantAndRevokeInSameOperation(t *testing.T) {
	ctx := context.Background()

	initDatabase(ctx, t)
	defer pool.ClosePool()

	// Insert a file with existing perms
	insertTestFile(t, ctx, "/somefile.txt", false, "Some file", "Content", `{"alice":"wrld","charlie":"r"}`)

	// Revoke charlie, grant bob
	input := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Path: llmfs.PathCriteria{Contains: "somefile"},
				Type: "file",
			},
			Operations: llmfs.Operations{
				Write: &llmfs.WriteOperation{
					Permissions: map[string]string{
						"charlie": "",
						"bob":     "r",
					},
				},
			},
		},
	}

	results, err := llmfs.PerformFilesystemOperations(ctx, "alice", "owner", input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Empty(t, results[0].Error)

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

	// Page 1
	input := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Path: llmfs.PathCriteria{Contains: "file"},
				Type: "file",
			},
			Pagination: &llmfs.Pagination{Page: 1, Limit: 2},
			Sort:       &llmfs.Sort{Field: "path", Direction: "asc"},
			Operations: llmfs.Operations{List: true},
		},
	}
	results, err := llmfs.PerformFilesystemOperations(ctx, "alice", "owner", input)
	require.NoError(t, err)
	require.Len(t, results, 1)
	op := results[0]
	require.Empty(t, op.Error)
	require.Len(t, op.Results, 2, "limit=2 => only 2 items: fileA, fileB")
	assert.Equal(t, "/fileA.txt", op.Results[0].Path)
	assert.Equal(t, "/fileB.txt", op.Results[1].Path)

	// Page 2
	input2 := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Path: llmfs.PathCriteria{Contains: "file"},
				Type: "file",
			},
			Pagination: &llmfs.Pagination{Page: 2, Limit: 2},
			Sort:       &llmfs.Sort{Field: "path", Direction: "asc"},
			Operations: llmfs.Operations{List: true},
		},
	}
	results2, err2 := llmfs.PerformFilesystemOperations(ctx, "alice", "owner", input2)
	require.NoError(t, err2)
	require.Len(t, results2, 1)
	op2 := results2[0]
	require.Empty(t, op2.Error)
	require.Len(t, op2.Results, 1, "Expect 1 leftover: fileC.txt")
	assert.Equal(t, "/fileC.txt", op2.Results[0].Path)
}

// TestParseTimeInvalidFormat checks how ParseTime handles nonsense strings.
func TestParseTimeInvalidFormat(t *testing.T) {
	invalid := llmfs.ParseTime("Not a real time string")
	require.True(t, invalid.IsZero(), "Should return zero time on invalid parse")
}
