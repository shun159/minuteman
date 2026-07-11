package cliconfig

import (
	"fmt"
	"net/netip"
	"strings"
)

// AddrList implements flag.Value so a flag can be repeated to accumulate a
// plain list of IP addresses, e.g. "-dns-server".
type AddrList []netip.Addr

func (a *AddrList) String() string {
	if a == nil {
		return ""
	}
	s := make([]string, len(*a))
	for i, addr := range *a {
		s[i] = addr.String()
	}
	return strings.Join(s, ",")
}

func (a *AddrList) Set(s string) error {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("parsing address %q: %w", s, err)
	}
	*a = append(*a, addr)
	return nil
}
