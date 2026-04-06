package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Paths    []string `yaml:"paths"`
	AllowAll bool     `yaml:"allow_all"`
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

	for i, p := range cfg.Paths {
		cfg.Paths[i] = os.ExpandEnv(p)
	}

	return &cfg, nil
}
