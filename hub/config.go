package hub

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents the Hub configuration options.
type Config struct {
	Addr              string   `json:"addr"`
	AuthToken         string   `json:"auth_token,omitempty"`
	RegistrationToken string   `json:"registration_token,omitempty"`
	AuthorizedKeysDir string   `json:"authorized_keys_dir,omitempty"`
	Debug             bool     `json:"debug,omitempty"`
	Peers             []string `json:"peers,omitempty"`
	MyURL             string   `json:"my_url,omitempty"`
	AdvertisePeers    bool     `json:"advertise_peers,omitempty"`
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

	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}

	return &cfg, nil
}
