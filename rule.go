package iptables

import (
	"fmt"
	"strconv"
)

type Rule struct {
	Source      string
	Destination string
	Protocol    string
	DstPort     int
	SrcPort     int
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

	if r.DstPort != 0 {
		switch r.Protocol {
		case "tcp", "udp":
			args = append(args, "--dport", strconv.Itoa(r.DstPort))
		default:
			return nil, fmt.Errorf("protocol must be tcp or udp")
		}
	}

	if r.SrcPort != 0 {
		switch r.Protocol {
		case "tcp", "udp":
			args = append(args, "--sport", strconv.Itoa(r.SrcPort))
		default:
			return nil, fmt.Errorf("protocol must be tcp or udp")
		}
	}

	if r.Jump != "" {
		args = append(args, "-j", r.Jump)
	} else {
		return nil, fmt.Errorf("jump must be specified")
	}

	return args, nil
}
