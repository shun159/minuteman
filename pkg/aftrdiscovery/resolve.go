package aftrdiscovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// parseDNSServers decodes an OPTION_DNS_SERVERS payload (RFC 3646 §3): a
// flat list of 16-byte IPv6 addresses.
func parseDNSServers(data []byte) ([]netip.Addr, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("aftrdiscovery: DNS servers option length %d is not a multiple of 16", len(data))
	}
	servers := make([]netip.Addr, 0, len(data)/16)
	for i := 0; i < len(data); i += 16 {
		addr, ok := netip.AddrFromSlice(data[i : i+16])
		if !ok {
			return nil, fmt.Errorf("aftrdiscovery: malformed address at offset %d", i)
		}
		servers = append(servers, addr)
	}
	return servers, nil
}

// resolveAFTR resolves name to an IPv6 address via a DNS AAAA lookup, using
// dnsServers (as learned from the same DHCPv6 Reply, per RFC 6334) if any
// were provided, or the system resolver otherwise. If the name resolves to
// multiple addresses, the first is used (RFC 6334 does not specify a
// selection policy).
func resolveAFTR(ctx context.Context, name string, dnsServers []netip.Addr) (netip.Addr, error) {
	resolver := net.DefaultResolver
	if len(dnsServers) > 0 {
		resolver = &net.Resolver{PreferGo: true, Dial: dialServers(dnsServers)}
	}

	addrs, err := resolver.LookupNetIP(ctx, "ip6", name)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolving AFTR name %q: %w", name, err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("AFTR name %q resolved to no addresses", name)
	}
	return addrs[0], nil
}

// dialServers returns a net.Resolver.Dial function that tries each of
// servers in order on port 53, ignoring the address the resolver itself
// would have used, and falling back to the next server on dial failure.
func dialServers(servers []netip.Addr) func(ctx context.Context, network, _ string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var lastErr error
		var d net.Dialer
		for _, s := range servers {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(s.String(), "53"))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("dialing DNS servers %v: %w", servers, lastErr)
	}
}
