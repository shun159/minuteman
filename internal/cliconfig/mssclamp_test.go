package cliconfig

import (
	"testing"

	"github.com/shun159/miniteman/pkg/datapath"
)

func TestParseMSSClamp(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{in: "auto", want: datapath.TCPMSSClampAuto},
		// An unset flag reaches us as "" only if a caller drops the default;
		// treat it as the default rather than an error.
		{in: "", want: datapath.TCPMSSClampAuto},
		{in: "off", want: 0},
		{in: "none", want: 0},
		{in: "0", want: 0},
		{in: "1420", want: 1420},
		{in: "536", want: minExplicitMSSClamp},
		{in: "65495", want: maxExplicitMSSClamp},

		// A value below RFC 1122's 536 is far likelier a typo (an MTU meant as
		// an MSS, say) than an intent, and "off" already expresses "no clamp".
		{in: "535", wantErr: true},
		{in: "65496", wantErr: true},
		{in: "-1", wantErr: true},
		{in: "1420bytes", wantErr: true},
		{in: "auto ", wantErr: true},
	}

	for _, tt := range tests {
		got, err := ParseMSSClamp(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseMSSClamp(%q) = %d, want an error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMSSClamp(%q): unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseMSSClamp(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
