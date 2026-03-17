package iptables

import (
	"strconv"
)

// Replace rule.
func (c *Config) Replace(rule *Rule, num int) error {
	ruleArgs, err := rule.GenArgs()
	if err != nil {
		return err
	}

	args := []string{"-t", c.Table, "-R", c.Chain, strconv.Itoa(num)}
	args = append(args, ruleArgs...)

	// logger
	c.Logger.Printf("Replacing iptables rule '%v' into table '%s' chain '%s'", num, c.Table, c.Chain)

	return c.Do(args)
}
