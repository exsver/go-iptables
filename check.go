package iptables

// Check rule.
func (c *Config) Check(rule *Rule) error {
	ruleArgs, err := rule.GenArgs()
	if err != nil {
		return err
	}

	args := []string{"-t", c.Table, "-C", c.Chain}
	args = append(args, ruleArgs...)

	return c.Do(args)
}
