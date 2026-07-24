package agent

import (
	"encoding/json"
	"fmt"
	"os"
)

// ParamRule defines security validation rules for dynamic command parameters.
type ParamRule struct {
	Regex         string   `json:"regex,omitempty"`
	AllowedValues []string `json:"allowed_values,omitempty"`
	Required      bool     `json:"required,omitempty"`
}

// CustomCommandConfig defines a configurable task executable or file-reader.
type CustomCommandConfig struct {
	Type           string               `json:"type,omitempty"`            // "" (exec) or "file_read"
	Executable     string               `json:"executable,omitempty"`      // Path to binary or script
	Args           []string             `json:"args,omitempty"`            // Static flags or template vars ($param_name)
	ParamRules     map[string]ParamRule `json:"param_rules,omitempty"`     // Input validation rules for params
	AllowedPaths   []string             `json:"allowed_paths,omitempty"`   // Allowed glob patterns for file_read
	MaxBytes       int64                `json:"max_bytes,omitempty"`       // Max file read size or output limit
	TimeoutSeconds int                  `json:"timeout_seconds,omitempty"` // Execution timeout
	Env            []string             `json:"env,omitempty"`             // Extra environment variables
}

// Config represents the Agent configuration.
type Config struct {
	HubURL             string                         `json:"hub_url"`
	AuthToken          string                         `json:"auth_token,omitempty"`
	PrivateKeyPath     string                         `json:"private_key_path,omitempty"`
	AgentID            string                         `json:"agent_id"`
	CachePath          string                         `json:"cache_path,omitempty"`
	InsecureSkipVerify bool                           `json:"insecure_skip_verify,omitempty"`
	Commands           map[string]CustomCommandConfig `json:"commands,omitempty"`
}

// LoadConfig reads the JSON configuration file from the specified path.
func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config JSON: %w", err)
	}

	if cfg.HubURL == "" {
		return nil, fmt.Errorf("config field 'hub_url' is required")
	}
	if cfg.AgentID == "" {
		return nil, fmt.Errorf("config field 'agent_id' is required")
	}

	if cfg.CachePath == "" {
		cfg.CachePath = "redborder-satellite-cache.json"
	}

	return &cfg, nil
}
