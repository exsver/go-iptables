package iptables

// Flush rules.
func (c *Config) Flush() error {
	args := []string{"-t", c.Table, "-F", c.Chain}

	// logger
	c.Logger.Printf("Flushing iptables table '%s' chain '%s'", c.Table, c.Chain)

	return c.Do(args)
}
