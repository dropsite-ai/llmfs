package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/dropsite-ai/llmfs"
	"github.com/dropsite-ai/llmfs/auth"
	"github.com/dropsite-ai/llmfs/config"
	"github.com/dropsite-ai/llmfs/migrate"
	"github.com/dropsite-ai/sqliteutils/pool"
	"github.com/fatih/color"
	"github.com/xeipuuv/gojsonschema"
)

//go:embed schema.json
var schemaFS embed.FS

func main() {
	// Flags.
	dbPath := flag.String("db", "llmfs.db", "SQLite database path")
	owner := flag.String("owner", "root", "Database owner username")
	authFlag := flag.String("auth", "", "Authentication URL")
	poolSize := flag.Int("pool", 1, "Size of DB pool")
	httpPort := flag.Int("port", 8080, "HTTP port to listen on")
	showSchema := flag.Bool("schema", false, "Show schema for LLM function call (and exit)")
	yamlPath := flag.String("yaml", "./llmfs.yaml", "YAML configuration path")
	flag.Parse()

	config.Load(*yamlPath)
	if *authFlag != "" {
		config.Cfg.AuthURL = *authFlag
	}
	config.Cfg.OwnerUser = *owner

	// Print logo.
	logo := color.New(color.FgBlack, color.BgHiCyan).SprintFunc()
	sub := color.New(color.FgHiWhite, color.Bold).SprintFunc()
	println(logo("🌌 LLMFS "), sub("by dropsite.ai"))

	ctx := context.Background()

	// Read embedded schema.
	schemaBytes, err := schemaFS.ReadFile("schema.json")
	if err != nil {
		log.Fatalf("Failed to read embedded schema: %v", err)
	}
	if *showSchema {
		hi := color.New(color.FgYellow, color.Bold).SprintFunc()
		code := color.New(color.Faint).SprintFunc()
		println(hi("-----BEGIN FUNCTION CALL JSON SCHEMA----"))
		println(code(string(schemaBytes)))
		println(hi("-----END FUNCTION CALL JSON SCHEMA----"))
		return
	}

	// Initialize the database pool.
	if err := pool.InitPool(*dbPath, *poolSize); err != nil {
		log.Fatalf("Failed to init database pool: %v", err)
	}
	defer func() {
		if err := pool.ClosePool(); err != nil {
			log.Fatalf("Failed to close pool: %v", err)
		}
	}()

	// Run database migrations.
	migrate.Migrate(ctx)

	// Create a JSON Schema loader.
	schemaLoader := gojsonschema.NewBytesLoader(schemaBytes)

	// Create a new ServeMux.
	mux := http.NewServeMux()

	// Public endpoint: /schema returns the embedded JSON schema.
	mux.HandleFunc("/schema", func(w http.ResponseWriter, r *http.Request) {
		f, err := schemaFS.Open("schema.json")
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read schema: %v", err), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read schema content: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	})

	// /auth endpoint.
	mux.HandleFunc("/auth", auth.AuthHandler)

	// /perform endpoint, protected by authMiddleware.
	mux.Handle("/perform", auth.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read and validate request body.
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		docLoader := gojsonschema.NewBytesLoader(bodyBytes)
		result, err := gojsonschema.Validate(schemaLoader, docLoader)
		if err != nil {
			http.Error(w, fmt.Sprintf("Schema validation error: %v", err), http.StatusInternalServerError)
			return
		}
		if !result.Valid() {
			var errs []string
			for _, desc := range result.Errors() {
				errs = append(errs, desc.String())
			}
			http.Error(w, fmt.Sprintf("Invalid input JSON:\n%s", errs), http.StatusBadRequest)
			return
		}

		var input []llmfs.FilesystemOperation
		if err = json.Unmarshal(bodyBytes, &input); err != nil {
			http.Error(w, fmt.Sprintf("JSON unmarshal error: %v", err), http.StatusBadRequest)
			return
		}

		// Get authenticated user from context.
		currentUser, ok := r.Context().Value(auth.UsernameKey).(string)
		if !ok || currentUser == "" {
			http.Error(w, "Failed to determine authenticated user", http.StatusInternalServerError)
			return
		}
		ownerUser := *owner
		results, err := llmfs.PerformFilesystemOperations(ctx, currentUser, ownerUser, input)
		if err != nil {
			http.Error(w, fmt.Sprintf("PerformFilesystemOperations error: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})))

	addr := fmt.Sprintf(":%d", *httpPort)
	log.Printf("Server listening on %d", *httpPort)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("ListenAndServe failed: %v", err)
	}
}
