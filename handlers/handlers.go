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

//go:embed schema/perform_request.json schema/perform_response.json
var schemaFS embed.FS

// Globals
var (
	performRequestSchema  interface{}             // Parsed JSON from perform_request.json (used for /system response)
	performResponseSchema interface{}             // Parsed JSON from perform_response.json (used for /system response)
	schemaLoader          gojsonschema.JSONLoader // For validating incoming requests (/perform)
)

func Register(ctx context.Context) http.Handler {
	// Preload and parse the input schema (function_input_schema.json).
	inputSchemaBytes, err := schemaFS.ReadFile("schema/perform_request.json")
	if err != nil {
		log.Fatalf("Failed to read embedded input schema: %v", err)
	}
	if err = json.Unmarshal(inputSchemaBytes, &performRequestSchema); err != nil {
		log.Fatalf("Failed to parse input schema JSON: %v", err)
	}
	// Create a gojsonschema JSONLoader for validating incoming requests.
	schemaLoader = gojsonschema.NewBytesLoader(inputSchemaBytes)

	// Preload and parse the output schema (function_output_schema.json).
	outputSchemaBytes, err := schemaFS.ReadFile("schema/perform_response.json")
	if err != nil {
		log.Fatalf("Failed to read embedded output schema: %v", err)
	}
	if err := json.Unmarshal(outputSchemaBytes, &performResponseSchema); err != nil {
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
		resp := map[string]any{
			"system_instruction":      systemInstruction,
			"perform_request_schema":  performRequestSchema,
			"perform_response_schema": performResponseSchema,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})))

	// /auth endpoint to validate tokens.
	mux.HandleFunc("/auth", AuthHandler)

	// /perform endpoint: validated by the preloaded input schema.
	mux.Handle("/perform", AuthMiddleware(http.HandlerFunc(performHandler(ctx))))

	// Provide /ok status endpoint.
	mux.Handle("/ok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	}))

	return mux
}
