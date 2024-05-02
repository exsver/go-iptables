package iptables

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

type Config struct {
	// Path to iptables bin
	// Examples:
	//   "/usr/sbin/iptables"
	//   "/usr/sbin/ip6tables"
	Path string
	// Chain name
	// Examples:
	//   "INPUT"
	//   "FORWARD"
	//   "OUTPUT"
	Chain string
}

func (c *Config) String() string {
	return fmt.Sprintf("Path: '%s', Chain: '%s'", c.Path, c.Chain)
}

func NewConfig(path string, chain string) (*Config, error) {
	return &Config{
		Path:  path,
		Chain: chain,
	}, nil
}

func (c *Config) Exec(args []string) (string, string, error) {
	cmd := exec.CommandContext(context.Background(), c.Path, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("error while executing command: %v", err)
	}

	return stdout.String(), stderr.String(), nil
}
