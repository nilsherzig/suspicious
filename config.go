package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type PathConfig struct {
	Path          string   `yaml:"path"`
	AllowBinaries []string `yaml:"allow_binaries"`
}

// UnmarshalYAML supports both plain string and object format:
//
//	- /tmp/foo
//	- path: /tmp/foo
//	  allow_binaries: [/usr/bin/nvim]
func (p *PathConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		p.Path = value.Value
		return nil
	}
	type raw PathConfig
	return value.Decode((*raw)(p))
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

type Config struct {
	Paths    []PathConfig `yaml:"paths"`
	AllowAll bool         `yaml:"allow_all"`
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
