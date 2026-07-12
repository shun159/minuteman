package routeradvert

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// allNodesMulticast and allRoutersMulticast are the well-known link-local
// scope multicast addresses NDP routers send Advertisements to and listen
// for Solicitations on, respectively (RFC 4861 §4.1/§4.2).
var (
	allNodesMulticast   = netip.MustParseAddr("ff02::1")
	allRoutersMulticast = netip.MustParseAddr("ff02::2")
)

// icmp6Filter is Linux's ICMP6_FILTER sockopt name (<netinet/icmp6.h>), not
// exported by golang.org/x/sys/unix for Linux -- vendored here the same way
// bpf/uapi/linux/*.h vendors constants missing from the generated
// bpf/vmlinux.h.
const icmp6Filter = 1

// Conn is a raw ICMPv6 socket bound to one interface, used to send Router
// Advertisements and receive Router Solicitations on it. Not safe for
// concurrent use except Close, which may be called from another goroutine
// to unblock a blocked Solicitations reader.
type Conn struct {
	fd      int
	ifIndex int
}

// Listen opens a raw ICMPv6 socket bound to iface: joins the All-Routers
// multicast group (so multicast Router Solicitations reach it at all),
// sets both hop limits to 255 (RFC 4861 §6.1.2 requires this on every NDP
// packet, so receivers can detect off-link spoofing), and installs an
// ICMP6_FILTER that passes only Router Solicitation, so the read loop isn't
// woken by unrelated ICMPv6 traffic (echo, NS/NA, MLD).
func Listen(iface string) (*Conn, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("routeradvert: looking up interface %s: %w", iface, err)
	}

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
	if err != nil {
		return nil, fmt.Errorf("routeradvert: opening raw ICMPv6 socket: %w", err)
	}
	c := &Conn{fd: fd, ifIndex: ifi.Index}

	if err := unix.BindToDevice(fd, iface); err != nil {
		c.Close()
		return nil, fmt.Errorf("routeradvert: binding to %s: %w", iface, err)
	}

	mreq := &unix.IPv6Mreq{Multiaddr: allRoutersMulticast.As16(), Interface: uint32(ifi.Index)}
	if err := unix.SetsockoptIPv6Mreq(fd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, mreq); err != nil {
		c.Close()
		return nil, fmt.Errorf("routeradvert: joining all-routers multicast group on %s: %w", iface, err)
	}

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255); err != nil {
		c.Close()
		return nil, fmt.Errorf("routeradvert: setting multicast hop limit on %s: %w", iface, err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, 255); err != nil {
		c.Close()
		return nil, fmt.Errorf("routeradvert: setting unicast hop limit on %s: %w", iface, err)
	}

	var filt unix.ICMPv6Filter
	for i := range filt.Data {
		filt.Data[i] = 0xffffffff // block everything...
	}
	filt.Data[icmpTypeRouterSolicit/32] &^= 1 << (icmpTypeRouterSolicit % 32) // ...except Router Solicitation
	if err := unix.SetsockoptICMPv6Filter(fd, unix.SOL_ICMPV6, icmp6Filter, &filt); err != nil {
		c.Close()
		return nil, fmt.Errorf("routeradvert: setting ICMPv6 filter on %s: %w", iface, err)
	}

	return c, nil
}

// Close closes the underlying socket, unblocking any goroutine currently
// reading from Solicitations.
func (c *Conn) Close() error {
	return unix.Close(c.fd)
}

// LinkLocalAddr returns iface's own fe80::/10 unicast address (the one this
// package's own RA sends are sourced from -- see Listen's BindToDevice),
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
		// a socket to it (pkg/dnsproxy, when -dns-proxy is on) needs the
		// zone to disambiguate. The wire encoding this package's own RDNSS
		// option writes (NewRDNSS's As16()) ignores the zone, as it must --
		// it's local metadata, never sent on the wire.
		return addr.WithZone(iface), nil
	}
	return netip.Addr{}, fmt.Errorf("routeradvert: %s has no link-local IPv6 address", iface)
}

// Solicitations returns a channel that receives a value each time a Router
// Solicitation arrives. It's closed when the underlying socket is closed
// (whether via Close or a real read error) -- ending a range/select loop
// over it is how a caller notices the Conn is done. Sends are non-blocking
// and coalesced: a burst of Solicitations arriving faster than the
// receiver drains the channel collapses to a single pending signal, which
// is fine since a caller only ever needs to know "at least one RS arrived
// since I last checked", not how many.
func (c *Conn) Solicitations() <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		defer close(ch)
		buf := make([]byte, 512)
		for {
			n, _, err := unix.Recvfrom(c.fd, buf, 0)
			if err != nil {
				return
			}
			if !isRouterSolicitation(buf[:n]) {
				continue // shouldn't happen given the ICMP6_FILTER, but harmless if it does
			}
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
	return ch
}

// SendAdvertisement sends ra to the All-Nodes multicast address (RFC 4861
// §4.2: both unsolicited and solicited Advertisements may be multicast).
func (c *Conn) SendAdvertisement(ra *RouterAdvertisement) error {
	dst := &unix.SockaddrInet6{Addr: allNodesMulticast.As16(), ZoneId: uint32(c.ifIndex)}
	return unix.Sendto(c.fd, ra.Marshal(), 0, dst)
}
