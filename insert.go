package iptables

// Insert rule.
func (c *Config) Insert(rule *Rule, num int) error {
	ruleArgs, err := rule.GenArgs()
	if err != nil {
		return err
	}

	args := []string{"-I", c.Chain, string(num)}
	args = append(args, ruleArgs...)

	return c.Do(args)
}
