package routeradvert

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// AllNodesMulticast and AllRoutersMulticast are the well-known link-local
// scope multicast addresses NDP routers send Advertisements to and listen
// for Solicitations on, respectively (RFC 4861 §4.1/§4.2).
var (
	AllNodesMulticast   = netip.MustParseAddr("ff02::1")
	AllRoutersMulticast = netip.MustParseAddr("ff02::2")
)

// ICMP6Filter is Linux's ICMP6_FILTER sockopt name (<netinet/icmp6.h>), not
// exported by golang.org/x/sys/unix for Linux -- vendored here the same way
// bpf/uapi/linux/*.h vendors constants missing from the generated
// bpf/vmlinux.h.
const ICMP6Filter = 1

// SolicitationFilter is the ICMP6_FILTER an advertiser's raw ICMPv6 socket
// sets, passing only Router Solicitations, so it isn't woken by unrelated
// ICMPv6 traffic (echo, NS/NA, MLD).
func SolicitationFilter() *unix.ICMPv6Filter {
	var filt unix.ICMPv6Filter
	for i := range filt.Data {
		filt.Data[i] = 0xffffffff // block everything...
	}
	filt.Data[icmpTypeRouterSolicit/32] &^= 1 << (icmpTypeRouterSolicit % 32) // ...except Router Solicitation
	return &filt
}

// LinkLocalAddr returns iface's own fe80::/10 unicast address (the one an
// advertiser bound to iface sends its RAs from),
// zoned with iface. Its caller (cmd/minuteman) binds a DNS proxy to it and
// passes it back in as Config.RDNSSAddr (see NewRDNSS's own doc): a router's
// link-local address is explicitly a valid RDNSS entry per RFC 8106 §5.1,
// and unlike a global address it always exists regardless of which WAN
// provisioning model (DHCPv6-PD vs NDProxy) assigned this LAN interface its
// prefix, so callers don't need to know which one is active.
func LinkLocalAddr(iface string) (netip.Addr, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("routeradvert: looking up interface %s: %w", iface, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("routeradvert: listing addresses on %s: %w", iface, err)
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.To4() != nil || !ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		// Zoned: fe80::/10 is only unique per-interface, so a caller binding
		// a socket to it (internal/dnsproxy, when -dns-proxy is on) needs the
		// zone to disambiguate. The wire encoding this package's own RDNSS
		// option writes (NewRDNSS's As16()) ignores the zone, as it must --
		// it's local metadata, never sent on the wire.
		return addr.WithZone(iface), nil
	}
	return netip.Addr{}, fmt.Errorf("routeradvert: %s has no link-local IPv6 address", iface)
}
