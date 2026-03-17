package iptables

import (
	"reflect"
	"testing"
)

func TestRule_GenArgs(t *testing.T) {
	type fields struct {
		Source        string
		Destination   string
		Protocol      string
		DstPort       string
		SrcPort       string
		InInterface   string
		OutInterface  string
		Comment       string
		Jump          string
		ToDestination string
		ToSource      string
	}
	tests := []struct {
		name    string
		fields  fields
		want    []string
		wantErr bool
	}{
		{
			name: "s-d-j",
			fields: fields{
				Source:      "192.168.1.10/32",
				Destination: "192.168.1.20/32",
				Jump:        "DROP",
			},
			want:    []string{"-s", "192.168.1.10/32", "-d", "192.168.1.20/32", "-j", "DROP"},
			wantErr: false,
		},
		{
			name: "no-jump",
			fields: fields{
				Source:      "192.168.1.10/32",
				Destination: "192.168.1.20/32",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "dport",
			fields: fields{
				Destination: "192.168.1.200/32",
				Protocol:    "tcp",
				DstPort:     "22",
				Jump:        "DROP",
			},
			want:    []string{"-d", "192.168.1.200/32", "-p", "tcp", "--dport", "22", "-j", "DROP"},
			wantErr: false,
		},
		{
			name: "dst multiport",
			fields: fields{
				Destination: "192.168.1.222/32",
				Protocol:    "tcp",
				DstPort:     "21,22,111,1024:65535",
				Jump:        "DROP",
			},
			want:    []string{"-d", "192.168.1.222/32", "-p", "tcp", "-m", "multiport", "--dports", "21,22,111,1024:65535", "-j", "DROP"},
			wantErr: false,
		},
		{
			name: "src multiport",
			fields: fields{
				Source:   "192.168.1.100/32",
				Protocol: "tcp",
				SrcPort:  "21,22",
				Jump:     "DROP",
			},
			want:    []string{"-s", "192.168.1.100/32", "-p", "tcp", "-m", "multiport", "--sports", "21,22", "-j", "DROP"},
			wantErr: false,
		},
		{
			name: "dport-error",
			fields: fields{
				Destination: "192.168.1.200/32",
				DstPort:     "22",
				Jump:        "DROP",
			},
			want:    nil,
			wantErr: true, // tcp or udp required
		},
		{
			name: "comment",
			fields: fields{
				Destination: "192.168.1.200/32",
				Protocol:    "tcp",
				DstPort:     "22",
				Comment:     "deny ssh",
				Jump:        "DROP",
			},
			want:    []string{"-d", "192.168.1.200/32", "-p", "tcp", "--dport", "22", "-m", "comment", "--comment", "'deny ssh'", "-j", "DROP"},
			wantErr: false,
		},
		{
			name: "comment with quotes",
			fields: fields{
				Destination: "192.168.1.200/32",
				Protocol:    "tcp",
				DstPort:     "22",
				Comment:     "deny 'ssh'",
				Jump:        "DROP",
			},
			want:    []string{"-d", "192.168.1.200/32", "-p", "tcp", "--dport", "22", "-m", "comment", "--comment", "'deny \"ssh\"'", "-j", "DROP"},
			wantErr: false,
		},
		{
			name: "nat",
			fields: fields{
				Source:       "192.168.1.0/24",
				OutInterface: "eth0",
				Jump:         "SNAT",
				ToSource:     "88.88.88.88",
			},

			want:    []string{"-s", "192.168.1.0/24", "-o", "eth0", "-j", "SNAT", "--to-source", "88.88.88.88"},
			wantErr: false,
		},
		{
			name: "port forwarding",
			fields: fields{
				Destination:   "88.88.88.88/32",
				Protocol:      "tcp",
				DstPort:       "22",
				Jump:          "DNAT",
				ToDestination: "192.168.1.201:22",
			},
			want:    []string{"-d", "88.88.88.88/32", "-p", "tcp", "--dport", "22", "-j", "DNAT", "--to-destination", "192.168.1.201:22"},
			wantErr: false,
		},
		{
			name: "RAWDNAT",
			fields: fields{
				Destination:   "100.100.100.100/32",
				Protocol:      "tcp",
				DstPort:       "80,443",
				Jump:          "RAWDNAT",
				ToDestination: "127.100.100.100/32",
			},
			want:    []string{"-d", "100.100.100.100/32", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "RAWDNAT", "--to-destination", "127.100.100.100/32"},
			wantErr: false,
		},
		{
			name: "RAWSNAT",
			fields: fields{
				Source:   "127.100.100.100/32",
				Jump:     "RAWSNAT",
				ToSource: "100.100.100.100/32",
			},
			want:    []string{"-s", "127.100.100.100/32", "-j", "RAWSNAT", "--to-source", "100.100.100.100/32"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Rule{
				Source:        tt.fields.Source,
				Destination:   tt.fields.Destination,
				Protocol:      tt.fields.Protocol,
				DstPort:       tt.fields.DstPort,
				SrcPort:       tt.fields.SrcPort,
				InInterface:   tt.fields.InInterface,
				OutInterface:  tt.fields.OutInterface,
				Comment:       tt.fields.Comment,
				Jump:          tt.fields.Jump,
				ToDestination: tt.fields.ToDestination,
				ToSource:      tt.fields.ToSource,
			}

			got, err := r.GenArgs()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenArgs() got = %v, want %v", got, tt.want)
			}
		})
	}
}
