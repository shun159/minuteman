// Package cliconfig parses minuteman's command-line flag values into typed
// configuration. It exists so cmd/minuteman/main.go can stay a thin wiring
// layer between flag definitions and the pkg/datapath API.
package cliconfig

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// LANSpec is a parsed "-lan" flag value: iface=gatewayIP[/prefixlen][,mtu],
// e.g. "eth1=192.168.1.1,1500" or "eth1=192.168.1.1/24". The prefix length
// is only consulted by the DHCPv4 server (-dhcpv4), which carves its address
// pool from Subnet; the DS-Lite datapath itself needs only GatewayIP. An
// omitted prefix length on an IPv4 gateway defaults Subnet to a /24 (the
// conventional home-LAN size).
type LANSpec struct {
	Iface     string
	GatewayIP netip.Addr
	Subnet    netip.Prefix // the LAN subnet for DHCPv4; invalid if GatewayIP isn't IPv4
	MTU       int          // 0 means "use the interface's current MTU"
}

// ParseLANSpec parses a single "-lan" flag value.
func ParseLANSpec(s string) (LANSpec, error) {
	ifacePart, rest, ok := strings.Cut(s, "=")
	if !ok {
		return LANSpec{}, fmt.Errorf("expected iface=gatewayIP[/prefixlen][,mtu], got %q", s)
	}

	ipPart, mtuPart, hasMTU := strings.Cut(rest, ",")
	addrPart, maskPart, hasMask := strings.Cut(ipPart, "/")
	ip, err := netip.ParseAddr(addrPart)
	if err != nil {
		return LANSpec{}, fmt.Errorf("parsing gateway IP in %q: %w", s, err)
	}

	var subnet netip.Prefix
	switch {
	case hasMask:
		bits, err := strconv.Atoi(maskPart)
		if err != nil {
			return LANSpec{}, fmt.Errorf("parsing prefix length in %q: %w", s, err)
		}
		subnet, err = ip.Prefix(bits)
		if err != nil {
			return LANSpec{}, fmt.Errorf("invalid prefix length in %q: %w", s, err)
		}
	case ip.Is4():
		subnet = netip.PrefixFrom(ip, 24).Masked() // default /24 for an IPv4 gateway
	}

	mtu := 0
	if hasMTU {
		mtu, err = strconv.Atoi(mtuPart)
		if err != nil {
			return LANSpec{}, fmt.Errorf("parsing MTU in %q: %w", s, err)
		}
	}

	return LANSpec{Iface: ifacePart, GatewayIP: ip, Subnet: subnet, MTU: mtu}, nil
}

// LANSpecList implements flag.Value so "-lan" can be repeated on the command
// line, accumulating one LANSpec per occurrence.
type LANSpecList []LANSpec

func (l *LANSpecList) String() string {
	if l == nil {
		return ""
	}
	ifaces := make([]string, len(*l))
	for i, s := range *l {
		ifaces[i] = s.Iface
	}
	return strings.Join(ifaces, ",")
}

func (l *LANSpecList) Set(s string) error {
	spec, err := ParseLANSpec(s)
	if err != nil {
		return err
	}
	*l = append(*l, spec)
	return nil
}
