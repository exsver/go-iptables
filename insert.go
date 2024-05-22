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

	args := []string{"-I", c.Chain, strconv.Itoa(num)}
	args = append(args, ruleArgs...)

	// logger
	c.Logger.Printf("Inserting iptables rule '%s' into chain '%s'", strings.Join(ruleArgs, " "), c.Chain)

	return c.Do(args)
}
