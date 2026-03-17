package iptables

import (
	"strconv"
	"strings"
)

// Insert rule.
func (c *Config) Insert(rule *Rule, num int) error {
	ruleArgs, err := rule.GenArgs()
	if err != nil {
		return err
	}

	args := []string{"-t", c.Table, "-I", c.Chain, strconv.Itoa(num)}
	args = append(args, ruleArgs...)

	// logger
	c.Logger.Printf("Inserting iptables rule '%s' into table '%s' chain '%s'", strings.Join(ruleArgs, " "), c.Table, c.Chain)

	return c.Do(args)
}
