package iptables

// Flush rules.
func (c *Config) Flush() error {
	args := []string{"-F", c.Chain}

	// logger
	c.Logger.Printf("Flushing iptables chain '%s'", c.Chain)

	return c.Do(args)
}
