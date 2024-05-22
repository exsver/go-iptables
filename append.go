package iptables

import "strings"

// Append rule.
func (c *Config) Append(rule *Rule) error {
	ruleArgs, err := rule.GenArgs()
	if err != nil {
		return err
	}

	args := []string{"-A", c.Chain}
	args = append(args, ruleArgs...)

	// logger
	c.Logger.Printf("Appending iptables rule '%s' to chain '%s'", strings.Join(ruleArgs, " "), c.Chain)

	return c.Do(args)
}
