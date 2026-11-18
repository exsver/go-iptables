package iptables

import (
	"fmt"
	"strings"
)

type Rule struct {
	Source        string
	Destination   string
	Protocol      string
	DstPort       string
	SrcPort       string
	InInterface   string
	OutInterface  string
	MatchSet      string // ipset name, e.g. "whitelist"
	MatchSetFlags string // "src", "dst", "src,dst", ...
	Comment       string
	Jump          string
	ToDestination string // nat
	ToSource      string // nat
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

	if r.DstPort != "" {
		switch r.Protocol {
		case "tcp", "udp":
			ports := strings.Split(r.DstPort, ",")
			if len(ports) == 1 {
				args = append(args, "--dport", strings.TrimSpace(r.DstPort))
			} else {
				args = append(args, "-m", "multiport", "--dports", strings.Join(ports, ","))
			}
		default:
			return nil, fmt.Errorf("protocol must be tcp or udp")
		}
	}

	if r.SrcPort != "" {
		switch r.Protocol {
		case "tcp", "udp":
			ports := strings.Split(r.SrcPort, ",")
			if len(ports) == 1 {
				args = append(args, "--sport", strings.TrimSpace(r.SrcPort))
			} else {
				args = append(args, "-m", "multiport", "--sports", strings.Join(ports, ","))
			}
		default:
			return nil, fmt.Errorf("protocol must be tcp or udp")
		}
	}

	if r.InInterface != "" {
		args = append(args, "-i", r.InInterface)
	}

	if r.OutInterface != "" {
		args = append(args, "-o", r.OutInterface)
	}

	if r.MatchSet != "" {
		if r.MatchSetFlags == "" {
			return nil, fmt.Errorf("match set flags must be specified")
		}
		args = append(args, "-m", "set", "--match-set", r.MatchSet, r.MatchSetFlags)
	} else if r.MatchSetFlags != "" {
		return nil, fmt.Errorf("match set must be specified")
	}

	if r.Comment != "" {
		args = append(args, "-m", "comment", "--comment", r.Comment)
	}

	if r.Jump != "" {
		args = append(args, "-j", r.Jump)
	} else {
		return nil, fmt.Errorf("jump must be specified")
	}

	if r.ToDestination != "" {
		args = append(args, "--to-destination", r.ToDestination)
	}

	if r.ToSource != "" {
		args = append(args, "--to-source", r.ToSource)
	}

	return args, nil
}
