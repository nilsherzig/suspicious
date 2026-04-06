package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

// ParentChain is a slice of process names serialized as a comma-separated string.
// Example YAML:  - git,lazygit,zsh
type ParentChain []string

func (c *ParentChain) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	*c = parts
	return nil
}

func (c ParentChain) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.Join(c, ","))
}

type PathConfig struct {
	Path              string        `json:"path"`
	AllowBinaries     []string      `json:"allow_binaries,omitempty"`
	AllowParentChains []ParentChain `json:"allow_parent_chains,omitempty"`
}

// UnmarshalJSON supports both plain string and object format:
//
//	- /tmp/foo
//	- path: /tmp/foo
//	  allow_binaries: [/usr/bin/nvim]
func (p *PathConfig) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		p.Path = s
		return nil
	}
	type raw PathConfig
	return json.Unmarshal(data, (*raw)(p))
}

func (p *PathConfig) isBinaryAllowed(exePath string) bool {
	if exePath == "" {
		return false
	}
	for _, b := range p.AllowBinaries {
		if b == exePath {
			return true
		}
	}
	return false
}

func (p *PathConfig) isParentChainAllowed(tree []ProcessInfo) bool {
	for _, chain := range p.AllowParentChains {
		if matchesChain(tree, chain) {
			return true
		}
	}
	return false
}

func matchesChain(tree []ProcessInfo, chain ParentChain) bool {
	if len(chain) > len(tree) {
		return false
	}
	for i, name := range chain {
		if tree[i].Name != name {
			return false
		}
	}
	return true
}

type Config struct {
	Paths    []PathConfig `json:"paths"`
	AllowAll bool         `json:"allow_all,omitempty"`
}

func (c *Config) findPathConfig(filePath string) *PathConfig {
	for i := range c.Paths {
		p := &c.Paths[i]
		if filePath == p.Path || strings.HasPrefix(filePath, p.Path+"/") {
			return p
		}
	}
	return nil
}

func (c *Config) addParentChain(filePath string, chain ParentChain, configPath string) error {
	pc := c.findPathConfig(filePath)
	if pc == nil {
		return fmt.Errorf("kein Pfad-Eintrag für %s gefunden, chain nicht gespeichert", filePath)
	}
	pc.AllowParentChains = append(pc.AllowParentChains, chain)

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config serialisieren: %w", err)
	}
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("config schreiben: %w", err)
	}
	return nil
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config lesen: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config parsen: %w", err)
	}

	if len(cfg.Paths) == 0 {
		return nil, fmt.Errorf("keine Pfade in config angegeben")
	}

	for i := range cfg.Paths {
		cfg.Paths[i].Path = os.ExpandEnv(cfg.Paths[i].Path)
		for j, b := range cfg.Paths[i].AllowBinaries {
			cfg.Paths[i].AllowBinaries[j] = os.ExpandEnv(b)
		}
	}

	return &cfg, nil
}
