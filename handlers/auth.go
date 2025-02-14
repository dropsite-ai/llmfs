package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dropsite-ai/llmfs"
	"github.com/dropsite-ai/llmfs/config"
	"github.com/golang-jwt/jwt"
)

// Define a regex for Linux username restrictions.
// This regex enforces:
//   - 1 to 32 characters
//   - Starts with a lowercase letter or underscore
//   - Contains only lowercase letters, digits, underscores, or dashes.
var usernameRegex = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func validateUsername(username string) error {
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("invalid username: %q", username)
	}
	return nil
}

// trimBearer removes any "Bearer " prefix from a token.
func trimBearer(token string) string {
	if strings.HasPrefix(token, "Bearer ") {
		return token[7:]
	}
	return token
}

// verifyJWT validates a JWT token string using the given secret and returns the "username" claim.
func verifyJWT(tokenStr, secret string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return "", errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}
	username, ok := claims["username"].(string)
	if !ok {
		return "", errors.New("username not found in token")
	}
	// Validate the username here.
	if err := validateUsername(username); err != nil {
		return "", err
	}
	return username, nil
}

// getUserSecret retrieves the per-user secret from the virtual filesystem.
// It assumes the user file is stored at "/llmfs/users/<username>.json" and contains a JSON property "jwt_secret".
func getUserSecret(username string) (string, error) {
	ctx := context.Background()
	userPath := fmt.Sprintf("/llmfs/users/%s.json", username)

	// Build a single FilesystemOperation with a 'read' sub-operation
	fsOps := []llmfs.FilesystemOperation{
		{
			Match: llmfs.MatchCriteria{
				Type: "file",
				Path: llmfs.PathCriteria{
					Exactly: userPath,
				},
			},
			Operations: []llmfs.SubOperation{
				{
					Operation: "read",
				},
			},
		},
	}

	results, err := llmfs.PerformFilesystemOperations(ctx, config.Cfg.OwnerUser, config.Cfg.OwnerUser, fsOps)
	if err != nil {
		return "", err
	}
	if len(results) == 0 || len(results[0].SubOpResults) == 0 {
		return "", fmt.Errorf("no results returned when reading user file %s", userPath)
	}
	subOpRes := results[0].SubOpResults[0]
	if len(subOpRes.Results) == 0 {
		// Possibly means file doesn't exist or no permission
		if subOpRes.Error != "" {
			return "", fmt.Errorf("error reading user file %s: %s", userPath, subOpRes.Error)
		}
		return "", fmt.Errorf("user file %s is empty or not found", userPath)
	}

	secretJSON := subOpRes.Results[0].Content
	var data struct {
		JWTSecret string `json:"jwt_secret"`
	}
	if err := json.Unmarshal([]byte(secretJSON), &data); err != nil {
		return "", err
	}
	if data.JWTSecret == "" {
		return "", fmt.Errorf("no jwt_secret found in user file %s", userPath)
	}
	return data.JWTSecret, nil
}

// authenticate checks the provided token and returns the username if authentication succeeds.
// It first tries to verify using the root config secret. If that doesn’t work and the token’s username is not "root":
//   - If the global authURL is set, it forwards the token to that URL’s /auth endpoint.
//   - Otherwise it attempts to authenticate locally via a per-user secret stored in the virtual filesystem.
func authenticate(tokenStr string) (string, error) {
	tokenStr = trimBearer(tokenStr)

	// 1) Try to verify using the config secret.
	if username, err := verifyJWT(tokenStr, config.Cfg.JWTSecret); err == nil && username == "root" {
		return "root", nil
	}

	// 2) Not root => check external auth if configured
	if config.Cfg.AuthURL != "" {
		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequest("GET", config.Cfg.AuthURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("external auth failed with status %d", resp.StatusCode)
		}
		var result struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", err
		}
		if result.Username == "" {
			return "", fmt.Errorf("external auth returned empty username")
		}
		return result.Username, nil
	}

	// 3) No external auth => local authentication with per-user secret.
	//    Extract the username from the token *without verifying* first.
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}
	usernameClaim, ok := claims["username"].(string)
	if !ok || usernameClaim == "" {
		return "", fmt.Errorf("username claim missing")
	}

	// 4) Load that user’s JWT secret from the fs
	userSecret, err := getUserSecret(usernameClaim)
	if err != nil {
		return "", fmt.Errorf("failed to get user secret: %v", err)
	}

	// 5) Verify token using user-specific secret
	verifiedUsername, err := verifyJWT(tokenStr, userSecret)
	if err != nil {
		return "", fmt.Errorf("failed to verify token with user secret: %v", err)
	}
	return verifiedUsername, nil
}

// AuthHandler is the HTTP handler for /auth.
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}
	username, err := authenticate(tokenStr)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	resp := map[string]string{"username": username}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// AuthMiddleware wraps handlers to enforce authentication.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}
		username, err := authenticate(tokenStr)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), UsernameKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
