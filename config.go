package iptables

import "fmt"

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
