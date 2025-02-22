package permissions_test

import (
	"context"
	"testing"

	"github.com/dropsite-ai/llmfs/migrate"
	"github.com/dropsite-ai/llmfs/permissions"
	"github.com/dropsite-ai/sqliteutils/exec"
	"github.com/dropsite-ai/sqliteutils/pool"
	"github.com/dropsite-ai/sqliteutils/test"
	"github.com/stretchr/testify/require"
)

// initDatabase spins up an in-memory SQLite DB and applies migrations.
func initDatabase(ctx context.Context, t *testing.T) {
	err := test.Pool(ctx, t, "", 1)
	require.NoError(t, err, "failed to init test DB pool")
	migrate.Migrate(ctx)
}

// createFile inserts a row in the filesystem table with a given path & permission JSON (if any).
func createFile(t *testing.T, ctx context.Context, path string, isDir bool, permJSON string) {
	q := `
INSERT INTO filesystem (path, is_directory, permissions, created_at, updated_at)
VALUES (:path, :isd, :perm, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
`
	params := map[string]interface{}{
		":path": path,
		":isd":  0,
		":perm": permJSON,
	}
	if isDir {
		params[":isd"] = 1
	}
	err := exec.Exec(ctx, q, params, nil)
	require.NoError(t, err, "failed to create file/dir %q", path)
}

func TestBuildGrantAndRevokePermissionQueries(t *testing.T) {
	// This test checks the direct query-building functions:
	// BuildGrantPermissionQuery and BuildRevokePermissionQuery.
	grantQs, grantParams := permissions.BuildGrantPermissionQuery(
		"/somepath", "bob", "wrld", 0, 1,
	)
	require.Len(t, grantQs, 1)
	require.Len(t, grantParams, 1)

	revokeQs, revokeParams := permissions.BuildRevokePermissionQuery(
		"/somepath", "alice", 0, 2,
	)
	require.Len(t, revokeQs, 1)
	require.Len(t, revokeParams, 1)

	t.Logf("Grant Query:   %s\nParams: %+v", grantQs[0], grantParams[0])
	t.Logf("Revoke Query:  %s\nParams: %+v", revokeQs[0], revokeParams[0])
}

func TestGrantAndRevokePermission(t *testing.T) {
	ctx := context.Background()
	initDatabase(ctx, t)
	defer pool.ClosePool()

	// Create a file with no permissions.
	createFile(t, ctx, "/secret.txt", false, `"{ }"`) // or "{}" – using a string for empty JSON object

	// 1) Grant "r" to "alice"
	err := permissions.GrantPermission(ctx, "/secret.txt", "alice", "r")
	require.NoError(t, err, "GrantPermission should succeed")

	// 2) Check the DB to confirm the JSON was updated.
	var permString string
	err = exec.Exec(ctx, `SELECT permissions FROM filesystem WHERE path = :p`, map[string]interface{}{":p": "/secret.txt"}, func(_ int, row map[string]interface{}) {
		permString, _ = row["permissions"].(string)
	})
	require.NoError(t, err)
	require.Contains(t, permString, `"alice":"r"`)

	// 3) Revoke "alice"
	err = permissions.RevokePermission(ctx, "/secret.txt", "alice")
	require.NoError(t, err, "RevokePermission should succeed")

	// 4) Confirm DB no longer has "alice"
	err = exec.Exec(ctx, `SELECT permissions FROM filesystem WHERE path = :p`, map[string]interface{}{":p": "/secret.txt"}, func(_ int, row map[string]interface{}) {
		permString, _ = row["permissions"].(string)
	})
	require.NoError(t, err)
	require.NotContains(t, permString, "alice")
}

func TestHasPermission(t *testing.T) {
	ctx := context.Background()
	initDatabase(ctx, t)
	defer pool.ClosePool()

	// Create a directory /docs with "alice": "wrl" and a sub-file /docs/secret.txt with empty perms.
	createFile(t, ctx, "/docs", true, `{"alice":"wrl"}`)
	createFile(t, ctx, "/docs/secret.txt", false, `{}`)

	// 1) Confirm that HasPermission sees "alice" has "r" on /docs directly.
	canRead, err := permissions.HasPermission(ctx, "alice", "/docs", "r")
	require.NoError(t, err)
	require.True(t, canRead, "alice has 'r' at /docs")

	// 2) Confirm that HasPermission inherits from parent for /docs/secret.txt:
	canRead, err = permissions.HasPermission(ctx, "alice", "/docs/secret.txt", "r")
	require.NoError(t, err)
	require.True(t, canRead, "alice should inherit read from /docs")

	// 3) "bob" tries to read the same file => should fail
	canRead, err = permissions.HasPermission(ctx, "bob", "/docs/secret.txt", "r")
	require.NoError(t, err)
	require.False(t, canRead, "bob does not have read perms")

	// 4) Let's test multiple required perms. "wrl" => includes 'w', 'r', 'l' but not 'd'.
	canWrite, err := permissions.HasPermission(ctx, "alice", "/docs/secret.txt", "w")
	require.NoError(t, err)
	require.True(t, canWrite, "alice inherits 'w' from /docs")

	canDelete, err := permissions.HasPermission(ctx, "alice", "/docs/secret.txt", "d")
	require.NoError(t, err)
	require.False(t, canDelete, "alice does not have 'd' in 'wrl'")

	// 5) If we grant "alice": "wrld" at /docs/secret.txt directly, it should override or supplement.
	err = permissions.GrantPermission(ctx, "/docs/secret.txt", "alice", "wrld")
	require.NoError(t, err)

	canDelete, err = permissions.HasPermission(ctx, "alice", "/docs/secret.txt", "d")
	require.NoError(t, err)
	require.True(t, canDelete, "alice now has 'd' at /docs/secret.txt itself")
}

func TestHasPermission_RootDirectory(t *testing.T) {
	// Confirm that we stop at "/" and do not find perms if not set anywhere.
	ctx := context.Background()
	initDatabase(ctx, t)
	defer pool.ClosePool()

	// Insert a path /stuff, no perms
	createFile(t, ctx, "/stuff", true, `{}`)

	canRead, err := permissions.HasPermission(ctx, "someone", "/stuff", "r")
	require.NoError(t, err)
	require.False(t, canRead, "No perms at /stuff nor at / => should fail")

	// Also confirm no error occurs if we search for a path that doesn't exist in the DB at all:
	// We'll just climb until we hit "/" and fail. The code attempts to load perms from each level.
	// But because none exist, result is false. No error is expected.
	canRead, err = permissions.HasPermission(ctx, "someone", "/nonexistent", "r")
	require.NoError(t, err)
	require.False(t, canRead)
	t.Log("HasPermission on nonexistent path => returns false without error (no perms found).")
}
