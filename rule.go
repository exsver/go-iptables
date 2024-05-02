package iptables

import "fmt"

type Rule struct {
	Source      string
	Destination string
	Protocol    string
	Jump        string
}

func (r *Rule) GenArgs() ([]string, error) {
	var args []string

	if r.Source != "" {
		args = append(args, "-s", r.Source)
	}

	if r.Destination != "" {
		args = append(args, "-d", r.Destination)
	}

	if r.Protocol != "" {
		args = append(args, "-p", r.Protocol)
	}

	if r.Jump != "" {
		args = append(args, "-j", r.Jump)
	} else {
		return nil, fmt.Errorf("jump must be specified")
	}

	return args, nil
}
