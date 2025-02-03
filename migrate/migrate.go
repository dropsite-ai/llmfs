package migrate

import (
	"context"
	"embed"
	"log"
	"strings"

	"github.com/dropsite-ai/sqliteutils/exec"
)

//go:embed migration.sql
var migrationFS embed.FS

func Migrate(ctx context.Context) {
	// Read embedded migration SQL
	migrationBytes, err := migrationFS.ReadFile("migration.sql")
	if err != nil {
		log.Fatalf("Failed to read migration: %v", err)
	}

	// Convert byte slice to string
	migrationString := string(migrationBytes)

	// Split string to get migrations
	migrations := strings.Split(migrationString, ";\n\n")

	// Execute migrations in a transaction
	err = exec.ExecMultiTx(ctx, migrations, make([]map[string]interface{}, len(migrations)), nil)
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
}
