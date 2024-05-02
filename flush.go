package iptables

// Flush rules.
func (c *Config) Flush() error {
	args := []string{"-F", c.Chain}

	return c.Do(args)
}
