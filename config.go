package llmfs

import (
	"log"

	"github.com/dropsite-ai/config"
	"github.com/dropsite-ai/yamledit"
	"gopkg.in/yaml.v3"
)

var ConfigNode *yaml.Node
var AuthEndpoint string
var Callbacks []config.CallbackDefinition
var Variables *config.Variables

var defaultYAML = []byte(`
variables:
  secrets:
    root: ""
`)

func LoadConfig(yamlPath string) {
	var err error
	ConfigNode, Variables, Callbacks, err = config.Load(yamlPath, defaultYAML)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	yamledit.ReadNode(ConfigNode, "auth_endpoint", &AuthEndpoint)
}

func SaveConfig(yamlPath string) {
	if err := config.Save(yamlPath, ConfigNode); err != nil {
		log.Fatalf("Error saving config: %v", err)
	}
}
