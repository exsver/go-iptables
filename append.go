package iptables

// Append rule.
func (c *Config) Append(rule *Rule) error {
	ruleArgs, err := rule.GenArgs()
	if err != nil {
		return err
	}

	args := []string{"-A", c.Chain}
	args = append(args, ruleArgs...)

	return c.Do(args)
}
