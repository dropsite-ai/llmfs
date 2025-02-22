package migrate_test

import (
	"context"
	"testing"

	"github.com/dropsite-ai/llmfs/migrate"
	"github.com/dropsite-ai/sqliteutils/pool"
	"github.com/dropsite-ai/sqliteutils/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateDatabase(t *testing.T) {
	ctx := context.Background()

	err := test.Pool(ctx, t, "", 1)
	require.NoError(t, err, "should create pool without error")
	defer func() {
		cerr := pool.ClosePool()
		assert.NoError(t, cerr, "closing pool should not fail")
	}()

	// Run the migration
	migrate.Migrate(ctx)
}
