package iptables

import "errors"

// Flush rules.
func (c *Config) Flush() error {
	args := []string{"-F", c.Chain}

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
