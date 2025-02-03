package config

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

// Config holds our YAML configuration.
type Config struct {
	JWTSecret string `yaml:"jwt_secret"` // used to verify root user token
	OwnerUser string `yaml:"owner_user"`
	AuthURL   string `yaml:"auth_url"`
}

var (
	Cfg Config
)

func Load(yamlPath string) {
	// Expand YAML path.
	expandedYAMLPath, err := expandPath(yamlPath)
	if err != nil {
		log.Fatalf("Failed to expand YAML path: %v", err)
	}

	// Generate YAML config if it doesn't exist.
	if _, err = os.Stat(expandedYAMLPath); os.IsNotExist(err) {
		var secret string
		secret, err = generateJWTSecret()
		if err != nil {
			log.Fatalf("Failed to generate JWT secret: %v", err)
		}
		Cfg = Config{
			JWTSecret: secret,
		}
		var data []byte
		data, err = yaml.Marshal(&Cfg)
		if err != nil {
			log.Fatalf("Failed to marshal YAML config: %v", err)
		}
		if err = os.WriteFile(expandedYAMLPath, data, 0600); err != nil {
			log.Fatalf("Failed to write YAML config: %v", err)
		}
		log.Printf("Generated new config at %s", expandedYAMLPath)
	} else {
		var data []byte
		data, err = os.ReadFile(expandedYAMLPath)
		if err != nil {
			log.Fatalf("Failed to read YAML config: %v", err)
		}
		if err = yaml.Unmarshal(data, &Cfg); err != nil {
			log.Fatalf("Failed to parse YAML config: %v", err)
		}
	}
}

// generateJWTSecret creates a secure random secret encoded as hex.
func generateJWTSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// expandPath expands a leading "~" in file paths.
func expandPath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[1:]), nil
	}
	return path, nil
}
