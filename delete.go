package iptables

import (
	"strconv"
	"strings"
)

// Delete rule by rule specification.
func (c *Config) Delete(rule *Rule) error {
	ruleArgs, err := rule.GenArgs()
	if err != nil {
		return err
	}

	args := []string{"-t", c.Table, "-D", c.Chain}
	args = append(args, ruleArgs...)

	// logger
	c.Logger.Printf("Deleting iptables rule '%s' from table '%s' chain '%s'", strings.Join(ruleArgs, " "), c.Table, c.Chain)

	return c.Do(args)
}

// DeleteByNum deletes rule by its number in the chain (1 = first).
func (c *Config) DeleteByNum(num int) error {
	args := []string{"-t", c.Table, "-D", c.Chain, strconv.Itoa(num)}

	// logger
	c.Logger.Printf("Deleting iptables rule '%v' from table '%s' chain '%s'", num, c.Table, c.Chain)

	return c.Do(args)
}
