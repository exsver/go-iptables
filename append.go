package iptables

import "strings"

// Append rule.
func (c *Config) Append(rule *Rule) error {
	ruleArgs, err := rule.GenArgs()
	if err != nil {
		return err
	}

	args := []string{"-t", c.Table, "-A", c.Chain}
	args = append(args, ruleArgs...)

	// logger
	c.Logger.Printf("Appending iptables rule '%s' into table '%s' chain '%s'", strings.Join(ruleArgs, " "), c.Table, c.Chain)

	return c.Do(args)
}
