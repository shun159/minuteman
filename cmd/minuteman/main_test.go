package main

import (
	"net/netip"
	"testing"
)

func TestNextB4(t *testing.T) {
	a := netip.MustParseAddr("2001:db8::1")
	b := netip.MustParseAddr("2001:db8::2")

	tests := []struct {
		name        string
		current     netip.Addr
		queried     netip.Addr
		ok          bool
		wantB4      netip.Addr
		wantChanged bool
	}{
		{
			name:        "genuine change",
			current:     a,
			queried:     b,
			ok:          true,
			wantB4:      b,
			wantChanged: true,
		},
		{
			name:        "same address is not a change",
			current:     a,
			queried:     a,
			ok:          true,
			wantB4:      a,
			wantChanged: false,
		},
		{
			// A momentarily-absent source (ok=false, e.g. mid-renumbering or a
			// netlink error) must keep the current B4, never switch to invalid.
			name:        "no source keeps current, even with a stale queried value",
			current:     a,
			queried:     b,
			ok:          false,
			wantB4:      a,
			wantChanged: false,
		},
		{
			name:        "invalid queried address keeps current",
			current:     a,
			queried:     netip.Addr{},
			ok:          true,
			wantB4:      a,
			wantChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotB4, gotChanged := nextB4(tt.current, tt.queried, tt.ok)
			if gotB4 != tt.wantB4 || gotChanged != tt.wantChanged {
				t.Errorf("nextB4(%v, %v, %v) = (%v, %v), want (%v, %v)",
					tt.current, tt.queried, tt.ok, gotB4, gotChanged, tt.wantB4, tt.wantChanged)
			}
		})
	}
}
