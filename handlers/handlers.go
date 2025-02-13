package handlers

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed function_input_schema.json function_output_schema.json
var schemaFS embed.FS

// Globals
var (
	inputSchemaData  interface{}             // Parsed JSON from function_input_schema.json (used for /system response)
	outputSchemaData interface{}             // Parsed JSON from function_output_schema.json (used for /system response)
	schemaLoader     gojsonschema.JSONLoader // For validating incoming requests (/perform)
)

func Register(ctx context.Context, owner string) http.Handler {
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
	mux.Handle("/blobs", AuthMiddleware(http.HandlerFunc(InitiateBlobUploadHandler)))

	// Example: POST /blobs/chunk => write blob chunk (requires auth).
	mux.Handle("/blobs/chunk", AuthMiddleware(http.HandlerFunc(UploadBlobChunkHandler)))

	// Example: GET /blobs/signed => read blob by signature (requires auth).
	mux.Handle("/blobs/signed", AuthMiddleware(http.HandlerFunc(GetSignedBlobHandler)))

	// Provide /system endpoint to return the dummy system instruction + both schemas.
	mux.Handle("/system", AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/auth", AuthHandler)

	// /perform endpoint: validated by the preloaded input schema.
	mux.Handle("/perform", AuthMiddleware(http.HandlerFunc(performHandler(ctx, owner))))

	// Provide /ok status endpoint.
	mux.Handle("/ok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	}))

	return mux
}
