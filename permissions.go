package llmfs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dropsite-ai/sqliteutils/exec"
)

// HasPermission checks if 'user' has all letters in 'required' at 'path' or inherited from a parent path.
// E.g. required="r" -> user must have 'r'; required="rl" -> user must have 'r' and 'l', etc.
func HasPermission(ctx context.Context, user string, path string, required string) (bool, error) {
	for {
		// Load the JSON object from the 'permissions' column at this path.
		permMap, err := loadPermissionsMap(ctx, path)
		if err != nil {
			return false, fmt.Errorf("loadPermissionsMap(%s): %w", path, err)
		}

		if len(permMap) > 0 {
			// Check exact user or wildcard "*"
			level, ok := permMap[user]
			if !ok {
				level, ok = permMap["*"]
			}
			if ok {
				// If 'level' contains all letters in 'required', return true
				return checkPermissionLevel(level, required), nil
			}
		}

		// If not found, or user doesn't have the required letters, move one directory up
		if path == "/" {
			// Reached the root without finding sufficient permission
			return false, nil
		}
		path = parentPath(path)
	}
}

// GrantPermission overwrites or adds 'username' => 'newLevel' in the JSON object for 'path'.
func GrantPermission(ctx context.Context, path string, username string, newLevel string) error {
	if !validatePermissionString(newLevel) {
		return fmt.Errorf("invalid permission level: %s (must be a subset of 'wrld')", newLevel)
	}

	permMap, err := loadPermissionsMap(ctx, path)
	if err != nil {
		return fmt.Errorf("loadPermissionsMap(%s): %w", path, err)
	}

	// Write or overwrite this user’s permissions
	permMap[username] = newLevel

	return savePermissionsMap(ctx, path, permMap)
}

// RevokePermission removes 'username' from the permissions object at 'path'.
func RevokePermission(ctx context.Context, path string, username string) error {
	permMap, err := loadPermissionsMap(ctx, path)
	if err != nil {
		return fmt.Errorf("loadPermissionsMap(%s): %w", path, err)
	}

	delete(permMap, username)

	return savePermissionsMap(ctx, path, permMap)
}

// ------------------- Internal Helpers -------------------

// loadPermissionsMap reads the 'permissions' column (JSON object) for 'path'.
// Returns an empty map if none exists or if it’s invalid JSON.
func loadPermissionsMap(ctx context.Context, path string) (map[string]string, error) {
	query := `
        SELECT permissions
        FROM filesystem
        WHERE path = :path
    `
	params := map[string]interface{}{":path": path}

	var permString string
	var found bool
	err := exec.Exec(ctx, query, params, func(_ int, row map[string]interface{}) {
		if ps, ok := row["permissions"].(string); ok {
			permString = ps
			found = true
		}
	})
	if err != nil {
		return nil, err
	}
	if !found || permString == "" {
		return map[string]string{}, nil
	}

	// Parse as JSON object
	var permMap map[string]string
	if jerr := json.Unmarshal([]byte(permString), &permMap); jerr != nil {
		// If invalid JSON, treat as empty
		return map[string]string{}, nil
	}
	return permMap, nil
}

// savePermissionsMap marshals the permissions map back to JSON and updates the filesystem table.
func savePermissionsMap(ctx context.Context, path string, pm map[string]string) error {
	data, err := json.Marshal(pm)
	if err != nil {
		return fmt.Errorf("json.Marshal error: %w", err)
	}

	query := `
        UPDATE filesystem
        SET permissions = :permissions,
            updated_at = CURRENT_TIMESTAMP
        WHERE path = :path
    `
	params := map[string]interface{}{
		":permissions": string(data),
		":path":        path,
	}
	return exec.Exec(ctx, query, params, nil)
}

// checkPermissionLevel returns true if 'userLevel' contains all characters in 'required'.
func checkPermissionLevel(userLevel, required string) bool {
	for _, c := range required {
		if !strings.ContainsRune(userLevel, c) {
			return false
		}
	}
	return true
}

// validatePermissionString ensures 'newLevel' only has letters from "wrld".
func validatePermissionString(perm string) bool {
	if perm == "" {
		// For "granting" an empty string, prefer RevokePermission instead.
		return false
	}
	for _, c := range perm {
		if !strings.ContainsRune("wrld", c) {
			return false
		}
	}
	return true
}

// parentPath returns the parent directory for a given path, e.g. "/folder/file.txt" -> "/folder".
func parentPath(p string) string {
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "/"
	}
	idx := strings.LastIndex(p, "/")
	if idx <= 0 {
		return "/"
	}
	parent := p[:idx]
	if parent == "" {
		return "/"
	}
	return parent
}
