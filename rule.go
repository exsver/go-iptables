package iptables

import (
	"fmt"
	"strings"
)

type Rule struct {
	Command     string
	Num         int
	Source      string
	Destination string
	Protocol    string
	Jump        string
}

func (r *Rule) GenArgs() ([]string, error) {
	var args []string

	switch strings.ToLower(r.Command) {
	case "a", "append":
		args = append(args, "-A")
	case "d", "delete":
		args = append(args, "-D")
	case "i", "insert":
		args = append(args, "-I")
	case "r", "replace":
		args = append(args, "-R")
	default:
		return nil, fmt.Errorf("invalid command: '%s'", r.Command)
	}

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
