// Package agent wires collectors, detection, policy, executor and transport
// into the long-running daemon.
package agent

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

// Defaults.
const (
	DefaultConfigPath = "/etc/aegis/agent.yaml"
	DefaultDataDir    = "/var/lib/aegis"
)

// Config is /etc/aegis/agent.yaml.
type Config struct {
	ServerURL string `yaml:"server_url"`
	DataDir   string `yaml:"data_dir"`
	LogLevel  string `yaml:"log_level"` // debug|info|warn|error
}

// LoadConfig reads path (a missing file is not an error), then applies
// environment overrides AEGIS_SERVER_URL, AEGIS_DATA_DIR, AEGIS_LOG_LEVEL.
// Callers apply flag overrides afterwards.
func LoadConfig(path string) (Config, error) {
	c := Config{DataDir: DefaultDataDir, LogLevel: "info"}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(b, &c); err != nil {
			return c, err
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return c, err
	}
	if v := os.Getenv("AEGIS_SERVER_URL"); v != "" {
		c.ServerURL = v
	}
	if v := os.Getenv("AEGIS_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("AEGIS_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir
	}
	return c, nil
}
