package lanprefix

import (
	"net/netip"
	"testing"
)

func TestSubnetFor(t *testing.T) {
	cases := []struct {
		name      string
		delegated string
		index     int
		want      string
		wantErr   bool
	}{
		{"/56 index 0", "2001:db8:1234:5600::/56", 0, "2001:db8:1234:5600::/64", false},
		{"/56 index 1", "2001:db8:1234:5600::/56", 1, "2001:db8:1234:5601::/64", false},
		{"/56 index 255 (max)", "2001:db8:1234:5600::/56", 255, "2001:db8:1234:56ff::/64", false},
		{"/56 index 256 (over capacity)", "2001:db8:1234:5600::/56", 256, "", true},
		{"/60 index 0", "2001:db8:1234:5600::/60", 0, "2001:db8:1234:5600::/64", false},
		{"/60 index 15 (max)", "2001:db8:1234:5600::/60", 15, "2001:db8:1234:560f::/64", false},
		{"/60 index 16 (over capacity)", "2001:db8:1234:5600::/60", 16, "", true},
		{"/52 index 4095 (max)", "2001:db8:1230::/52", 4095, "2001:db8:1230:fff::/64", false},
		{"/48 index 0", "2001:db8:1234::/48", 0, "2001:db8:1234::/64", false},
		{"/64 index 0 (exact)", "2001:db8:1234:5600::/64", 0, "2001:db8:1234:5600::/64", false},
		{"/64 index 1 (no room)", "2001:db8:1234:5600::/64", 1, "", true},
		{"negative index", "2001:db8:1234:5600::/56", -1, "", true},
		{"IPv4 delegated (invalid)", "192.0.2.0/24", 0, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			delegated := netip.MustParsePrefix(c.delegated)
			got, err := SubnetFor(delegated, c.index)
			if c.wantErr {
				if err == nil {
					t.Fatalf("SubnetFor(%s, %d) = %v, want error", c.delegated, c.index, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SubnetFor(%s, %d): %v", c.delegated, c.index, err)
			}
			want := netip.MustParsePrefix(c.want)
			if got != want {
				t.Errorf("SubnetFor(%s, %d) = %s, want %s", c.delegated, c.index, got, want)
			}
		})
	}
}

func TestAssignedAddress(t *testing.T) {
	cases := []struct {
		name    string
		subnet  string
		want    string
		wantErr bool
	}{
		{"basic /64", "2001:db8:1234:5600::/64", "2001:db8:1234:5600::1", false},
		{"not a /64", "2001:db8:1234:5600::/56", "", true},
		{"IPv4 (invalid)", "192.0.2.0/24", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			subnet := netip.MustParsePrefix(c.subnet)
			got, err := AssignedAddress(subnet)
			if c.wantErr {
				if err == nil {
					t.Fatalf("AssignedAddress(%s) = %v, want error", c.subnet, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AssignedAddress(%s): %v", c.subnet, err)
			}
			want := netip.MustParseAddr(c.want)
			if got != want {
				t.Errorf("AssignedAddress(%s) = %s, want %s", c.subnet, got, want)
			}
		})
	}
}
