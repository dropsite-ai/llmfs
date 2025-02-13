package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/dropsite-ai/llmfs"
	"github.com/xeipuuv/gojsonschema"
)

func performHandler(ctx context.Context, owner string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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
		results, err := llmfs.PerformFilesystemOperations(ctx, currentUser, owner, operations)
		if err != nil {
			http.Error(w, fmt.Sprintf("PerformFilesystemOperations error: %v", err), http.StatusInternalServerError)
			return
		}

		// Return the results as JSON.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}

}
