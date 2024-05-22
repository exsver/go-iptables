package iptables

import (
	"fmt"
	"strings"
)

type Rule struct {
	Source      string
	Destination string
	Protocol    string
	DstPort     string
	SrcPort     string
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

	if r.DstPort != "" {
		switch r.Protocol {
		case "tcp", "udp":
			ports := strings.Split(r.DstPort, ",")
			if len(ports) == 1 {
				args = append(args, "--dport", strings.TrimSpace(r.DstPort))
			} else {
				portsString := ""
				for _, port := range ports {
					portsString += fmt.Sprintf(",%s", strings.TrimSpace(port))
				}
				args = append(args, "-m", "-multiport", "--dports", strings.Join(ports, ","))
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
				args = append(args, "--sport", r.SrcPort)
			} else {
				portsString := ""
				for _, port := range ports {
					portsString += fmt.Sprintf(",%s", strings.TrimSpace(port))
				}
				args = append(args, "-m", "-multiport", "--sports", strings.Join(ports, ","))
			}
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
