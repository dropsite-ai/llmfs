package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/dropsite-ai/llmfs/config"
	"github.com/dropsite-ai/llmfs/handlers"
	"github.com/dropsite-ai/llmfs/migrate"
	"github.com/dropsite-ai/sqliteutils/pool"
	"github.com/fatih/color"
)

func main() {
	// Flags.
	dbPath := flag.String("db", "llmfs.db", "SQLite database path")
	owner := flag.String("owner", "root", "Database owner username")
	authFlag := flag.String("auth", "", "Authentication URL")
	poolSize := flag.Int("pool", 1, "Size of DB pool")
	httpPort := flag.Int("port", 8080, "HTTP port to listen on")
	yamlPath := flag.String("yaml", "./llmfs.yaml", "YAML configuration path")
	flag.Parse()

	// Load our YAML config.
	config.Load(*yamlPath)
	if *authFlag != "" {
		config.Cfg.AuthURL = *authFlag
	}
	config.Cfg.OwnerUser = *owner

	// Print a banner.
	logo := color.New(color.FgBlack, color.BgHiCyan).SprintFunc()
	sub := color.New(color.FgHiWhite, color.Bold).SprintFunc()
	fmt.Println(logo("🌌 LLMFS "), sub("by dropsite.ai"))

	ctx := context.Background()

	// Initialize DB connection pool.
	if err := pool.InitPool(*dbPath, *poolSize); err != nil {
		log.Fatalf("Failed to init database pool: %v", err)
	}
	defer func() {
		if err := pool.ClosePool(); err != nil {
			log.Fatalf("Failed to close pool: %v", err)
		}
	}()

	// Run any necessary migrations on startup.
	migrate.Migrate(ctx)

	// Prepare our HTTP handlers.
	mux := handlers.Register(ctx, *owner)

	addr := fmt.Sprintf(":%d", *httpPort)
	log.Printf("Server listening on %d", *httpPort)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("ListenAndServe failed: %v", err)
	}
}
