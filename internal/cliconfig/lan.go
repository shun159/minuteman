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

// LANSpec is a parsed "-lan" flag value: iface=gatewayIP[,mtu],
// e.g. "eth1=192.168.1.1,1500".
type LANSpec struct {
	Iface     string
	GatewayIP netip.Addr
	MTU       int // 0 means "use the interface's current MTU"
}

// ParseLANSpec parses a single "-lan" flag value.
func ParseLANSpec(s string) (LANSpec, error) {
	ifacePart, rest, ok := strings.Cut(s, "=")
	if !ok {
		return LANSpec{}, fmt.Errorf("expected iface=gatewayIP[,mtu], got %q", s)
	}

	ipPart, mtuPart, hasMTU := strings.Cut(rest, ",")
	ip, err := netip.ParseAddr(ipPart)
	if err != nil {
		return LANSpec{}, fmt.Errorf("parsing gateway IP in %q: %w", s, err)
	}

	mtu := 0
	if hasMTU {
		mtu, err = strconv.Atoi(mtuPart)
		if err != nil {
			return LANSpec{}, fmt.Errorf("parsing MTU in %q: %w", s, err)
		}
	}

	return LANSpec{Iface: ifacePart, GatewayIP: ip, MTU: mtu}, nil
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
