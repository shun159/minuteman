package cliconfig

import (
	"net/netip"
	"testing"
)

func TestParseLANSpec(t *testing.T) {
	cases := []struct {
		in         string
		wantIface  string
		wantGW     string
		wantSubnet string // "" means invalid/unset
		wantMTU    int
	}{
		{"eth1=192.168.1.1", "eth1", "192.168.1.1", "192.168.1.0/24", 0},
		{"eth1=192.168.1.1,1460", "eth1", "192.168.1.1", "192.168.1.0/24", 1460},
		{"lan0=10.0.0.1/25", "lan0", "10.0.0.1", "10.0.0.0/25", 0},
		{"lan0=10.0.0.1/25,1400", "lan0", "10.0.0.1", "10.0.0.0/25", 1400},
		// An IPv6 gateway has no DHCPv4 subnet.
		{"eth1=fe80::1", "eth1", "fe80::1", "", 0},
	}
	for _, c := range cases {
		got, err := ParseLANSpec(c.in)
		if err != nil {
			t.Errorf("ParseLANSpec(%q): %v", c.in, err)
			continue
		}
		if got.Iface != c.wantIface || got.GatewayIP.String() != c.wantGW || got.MTU != c.wantMTU {
			t.Errorf("ParseLANSpec(%q) = %+v, want iface %s gw %s mtu %d", c.in, got, c.wantIface, c.wantGW, c.wantMTU)
		}
		if c.wantSubnet == "" {
			if got.Subnet.IsValid() {
				t.Errorf("ParseLANSpec(%q).Subnet = %v, want invalid", c.in, got.Subnet)
			}
		} else if got.Subnet != netip.MustParsePrefix(c.wantSubnet) {
			t.Errorf("ParseLANSpec(%q).Subnet = %v, want %s", c.in, got.Subnet, c.wantSubnet)
		}
	}
}

func TestParseLANSpecErrors(t *testing.T) {
	for _, in := range []string{
		"noequals",
		"eth1=not-an-ip",
		"eth1=192.168.1.1/notanumber",
		"eth1=192.168.1.1/99",
		"eth1=192.168.1.1,notanumber",
		"eth1=192.168.1.1,67",    // MTU below the IPv4 minimum of 68
		"eth1=192.168.1.1,70000", // MTU above the 16-bit option ceiling
		"eth1=192.168.1.1,-1",    // negative MTU
	} {
		if _, err := ParseLANSpec(in); err == nil {
			t.Errorf("ParseLANSpec(%q): want error, got nil", in)
		}
	}
}
