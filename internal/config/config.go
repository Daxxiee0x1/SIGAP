// Package config loads the agent configuration (JSON keeps the binary dependency-free).
package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Daxxiee0x1/SIGAP/internal/detector"
)

type Agent struct {
	NodeID          string         `json:"node_id"`
	ProcRoot        string         `json:"proc_root"`
	KeyFile         string         `json:"key_file"`
	Outbox          string         `json:"outbox"`
	LogFiles        []string       `json:"log_files"`
	ConfigFiles     []string       `json:"config_files"`
	MaxLogBytes     int64          `json:"max_log_bytes"`
	IntervalSeconds int            `json:"interval_seconds"`
	TriggerFile     string         `json:"trigger_file"`
	VaultURL        string         `json:"vault_url"`
	VaultTokenEnv   string         `json:"vault_token_env"`
	Rules           detector.Rules `json:"rules"`
}

func Load(path string) (*Agent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Agent{ProcRoot: "/proc", MaxLogBytes: 256 << 10, IntervalSeconds: 2}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if v := os.Getenv("SIGAP_NODE_ID"); v != "" {
		c.NodeID = v
	}
	if c.NodeID == "" || c.KeyFile == "" || c.Outbox == "" {
		return nil, fmt.Errorf("%s: node_id, key_file, dan outbox wajib diisi", path)
	}
	if c.IntervalSeconds < 1 {
		c.IntervalSeconds = 1
	}
	return c, nil
}
