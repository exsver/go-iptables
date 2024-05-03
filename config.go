package iptables

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
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
	// Logger - debug logger
	Logger *log.Logger
}

func (c *Config) String() string {
	return fmt.Sprintf("Path: '%s', Chain: '%s'", c.Path, c.Chain)
}

func NewConfig(path string, chain string) (*Config, error) {
	return &Config{
		Path:   path,
		Chain:  chain,
		Logger: log.New(io.Discard, "", 0),
	}, nil
}

func (c *Config) SetLogger(logger *log.Logger) {
	c.Logger = logger
}

func (c *Config) Do(args []string) error {
	stdout, stderr, err := c.Exec(args)
	if err != nil {
		return err
	}

	if stderr != "" {
		return errors.New(stderr)
	}

	if stdout != "" {
		return errors.New(stdout)
	}

	return nil
}

func (c *Config) Exec(args []string) (string, string, error) {
	c.Logger.Printf("exec %s %s", c.Path, strings.Join(args, " "))
	cmd := exec.CommandContext(context.Background(), c.Path, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		c.Logger.Printf("exec error '%s' '%s' '%s'", stdout.String(), stderr.String(), err.Error())
		return stdout.String(), stderr.String(), fmt.Errorf("error while executing command: %v", err)
	}

	return stdout.String(), stderr.String(), nil
}
