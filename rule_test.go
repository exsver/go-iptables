package iptables

import (
	"reflect"
	"testing"
)

func TestRule_GenArgs(t *testing.T) {
	type fields struct {
		Source      string
		Destination string
		Protocol    string
		Jump        string
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Rule{
				Source:      tt.fields.Source,
				Destination: tt.fields.Destination,
				Protocol:    tt.fields.Protocol,
				Jump:        tt.fields.Jump,
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
