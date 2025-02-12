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

// We embed both function_input_schema.json (for request validation) and function_output_schema.json (for describing our response).
//
//go:embed function_input_schema.json function_output_schema.json
var schemaFS embed.FS

// We'll keep these as globals so they can be shared easily.
var (
	inputSchemaData  interface{}             // Parsed JSON from function_input_schema.json (used for /system response)
	outputSchemaData interface{}             // Parsed JSON from function_output_schema.json (used for /system response)
	schemaLoader     gojsonschema.JSONLoader // For validating incoming requests (/perform)
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

	// Preload and parse the input schema (function_input_schema.json).
	inputSchemaBytes, err := schemaFS.ReadFile("function_input_schema.json")
	if err != nil {
		log.Fatalf("Failed to read embedded input schema: %v", err)
	}
	if err = json.Unmarshal(inputSchemaBytes, &inputSchemaData); err != nil {
		log.Fatalf("Failed to parse input schema JSON: %v", err)
	}
	// Create a gojsonschema JSONLoader for validating incoming requests.
	schemaLoader = gojsonschema.NewBytesLoader(inputSchemaBytes)

	// Preload and parse the output schema (function_output_schema.json).
	outputSchemaBytes, err := schemaFS.ReadFile("function_output_schema.json")
	if err != nil {
		log.Fatalf("Failed to read embedded output schema: %v", err)
	}
	if err := json.Unmarshal(outputSchemaBytes, &outputSchemaData); err != nil {
		log.Fatalf("Failed to parse output schema JSON: %v", err)
	}

	// Prepare our HTTP handlers.
	mux := http.NewServeMux()

	// Example: POST /blobs => create blob (requires auth).
	mux.Handle("/blobs", auth.AuthMiddleware(http.HandlerFunc(llmfs.InitiateBlobUploadHandler)))

	// Example: POST /blobs/chunk => write blob chunk (requires auth).
	mux.Handle("/blobs/chunk", auth.AuthMiddleware(http.HandlerFunc(llmfs.UploadBlobChunkHandler)))

	// Example: GET /blobs/signed => read blob by signature (requires auth).
	mux.Handle("/blobs/signed", auth.AuthMiddleware(http.HandlerFunc(llmfs.GetSignedBlobHandler)))

	// Provide /system endpoint to return the dummy system instruction + both schemas.
	mux.Handle("/system", auth.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		systemInstruction := "Call the perform_filesystem_operations function when the user's request can be implemented in one or more filesystem operations."

		// Build the response from our preloaded schemas
		resp := map[string]interface{}{
			"system_instruction":     systemInstruction,
			"function_input_schema":  inputSchemaData,
			"function_output_schema": outputSchemaData,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})))

	// /auth endpoint to validate tokens.
	mux.HandleFunc("/auth", auth.AuthHandler)

	// /perform endpoint: validated by the preloaded input schema.
	mux.Handle("/perform", auth.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Validate JSON against the preloaded schema via gojsonschema.
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

		// If valid, unmarshal into our operations slice.
		var operations []llmfs.FilesystemOperation
		if err = json.Unmarshal(bodyBytes, &operations); err != nil {
			http.Error(w, fmt.Sprintf("JSON unmarshal error: %v", err), http.StatusBadRequest)
			return
		}

		// Get the authenticated user from context.
		currentUser, ok := r.Context().Value(llmfs.UsernameKey).(string)
		if !ok || currentUser == "" {
			http.Error(w, "Failed to determine authenticated user", http.StatusInternalServerError)
			return
		}

		// Perform the filesystem operations.
		results, err := llmfs.PerformFilesystemOperations(ctx, currentUser, *owner, operations)
		if err != nil {
			http.Error(w, fmt.Sprintf("PerformFilesystemOperations error: %v", err), http.StatusInternalServerError)
			return
		}

		// Return the results as JSON.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})))

	// Provide /ok status endpoint.
	mux.Handle("/ok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	}))

	addr := fmt.Sprintf(":%d", *httpPort)
	log.Printf("Server listening on %d", *httpPort)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("ListenAndServe failed: %v", err)
	}
}
