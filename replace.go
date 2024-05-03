package iptables

import "strconv"

// Replace rule.
func (c *Config) Replace(rule *Rule, num int) error {
	ruleArgs, err := rule.GenArgs()
	if err != nil {
		return err
	}

	args := []string{"-R", c.Chain, strconv.Itoa(num)}
	args = append(args, ruleArgs...)

	return c.Do(args)
}
