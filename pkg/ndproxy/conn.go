package ndproxy

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// icmp6Filter is Linux's ICMP6_FILTER sockopt name (<netinet/icmp6.h>),
// not exported by golang.org/x/sys/unix for Linux -- vendored here the
// same way pkg/routeradvert vendors it.
const icmp6Filter = 1

// conn is a raw ICMPv6 socket bound to one interface, filtered to a
// single NDP message type. The WAN side uses one filtered to Neighbor
// Solicitations (plus an ALLMULTI membership -- see below); each LAN
// side uses one filtered to Neighbor Advertisements. Not safe for
// concurrent use except Close, which may be called from another
// goroutine to unblock a blocked reader.
type conn struct {
	fd      int
	ifIndex int
	mac     net.HardwareAddr

	// allmultiFD, when >= 0, is a companion AF_PACKET socket holding a
	// PACKET_MR_ALLMULTI membership on the interface. Neighbor
	// Solicitations are sent to the target's Solicited-Node multicast
	// group (RFC 4291 §2.7.1), a different group per target address --
	// the WAN conn can't join them all ahead of time, so it puts the
	// interface in all-multicast mode instead. Holding the membership
	// on a dedicated packet socket (rather than an IFF_ALLMULTI ioctl)
	// means the kernel drops it automatically when the socket closes,
	// even on crash. The packet socket has protocol 0, so it receives
	// nothing itself.
	allmultiFD int
}

// listen opens a raw ICMPv6 socket on iface filtered to icmpType, with
// hop limits at 255 (RFC 4861 §6.1.2's requirement on every NDP packet).
// With allMulticast, the interface is additionally put in all-multicast
// mode for the lifetime of the conn (see the allmultiFD field).
func listen(iface string, icmpType uint8, allMulticast bool) (*conn, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("ndproxy: looking up interface %s: %w", iface, err)
	}

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
	if err != nil {
		return nil, fmt.Errorf("ndproxy: opening raw ICMPv6 socket: %w", err)
	}
	c := &conn{fd: fd, ifIndex: ifi.Index, mac: ifi.HardwareAddr, allmultiFD: -1}

	if err := unix.BindToDevice(fd, iface); err != nil {
		c.Close()
		return nil, fmt.Errorf("ndproxy: binding to %s: %w", iface, err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255); err != nil {
		c.Close()
		return nil, fmt.Errorf("ndproxy: setting multicast hop limit on %s: %w", iface, err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, 255); err != nil {
		c.Close()
		return nil, fmt.Errorf("ndproxy: setting unicast hop limit on %s: %w", iface, err)
	}

	var filt unix.ICMPv6Filter
	for i := range filt.Data {
		filt.Data[i] = 0xffffffff // block everything...
	}
	filt.Data[icmpType/32] &^= 1 << (icmpType % 32) // ...except icmpType
	if err := unix.SetsockoptICMPv6Filter(fd, unix.SOL_ICMPV6, icmp6Filter, &filt); err != nil {
		c.Close()
		return nil, fmt.Errorf("ndproxy: setting ICMPv6 filter on %s: %w", iface, err)
	}

	if allMulticast {
		pfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("ndproxy: opening ALLMULTI holder socket: %w", err)
		}
		mreq := &unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_ALLMULTI}
		if err := unix.SetsockoptPacketMreq(pfd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq); err != nil {
			unix.Close(pfd)
			c.Close()
			return nil, fmt.Errorf("ndproxy: enabling all-multicast on %s: %w", iface, err)
		}
		c.allmultiFD = pfd
	}

	return c, nil
}

// Close closes the underlying sockets (dropping the ALLMULTI membership,
// if any), unblocking any goroutine blocked in readTargets' loop.
func (c *conn) Close() error {
	if c.allmultiFD >= 0 {
		unix.Close(c.allmultiFD)
		c.allmultiFD = -1
	}
	return unix.Close(c.fd)
}

// message is one received NDP message relevant to the proxy: the
// solicitation's or advertisement's Target Address, plus the IPv6 source
// address it came from (the unspecified address marks a DAD probe, whose
// answering advertisement must be multicast rather than solicited).
type message struct {
	target netip.Addr
	source netip.Addr
}

// readTargets reads messages of icmpType from c into ch until the socket
// is closed (whether via Close or a real read error), then closes ch.
// Malformed messages are skipped. Sends never block: if ch is full the
// message is dropped -- matching packetConn.readSolicitations, since NDP
// retransmits make a dropped message only a delay, not a lost one.
func (c *conn) readTargets(icmpType uint8, ch chan<- message) {
	defer close(ch)
	buf := make([]byte, 1500)
	for {
		n, from, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			return
		}
		target, err := parseTarget(buf[:n], icmpType)
		if err != nil {
			continue
		}
		var source netip.Addr
		if sa, ok := from.(*unix.SockaddrInet6); ok {
			source = netip.AddrFrom16(sa.Addr)
		}
		select {
		case ch <- message{target: target, source: source}:
		default:
		}
	}
}

// sendSolicitation sends a Neighbor Solicitation for target out c, to
// target's Solicited-Node multicast group.
func (c *conn) sendSolicitation(target netip.Addr) error {
	dst := &unix.SockaddrInet6{Addr: solicitedNodeMulticast(target).As16(), ZoneId: uint32(c.ifIndex)}
	return unix.Sendto(c.fd, marshalNeighborSolicitation(target, c.mac), 0, dst)
}

// sendAdvertisement sends the proxy's Neighbor Advertisement for target
// out c. Solicited advertisements go unicast back to the solicitor;
// unsolicited ones (answering a DAD-style solicitation from the
// unspecified address, or refreshing) go to the All-Nodes group, per
// RFC 4861 §7.2.4's destination rules.
func (c *conn) sendAdvertisement(target, solicitor netip.Addr) error {
	solicited := solicitor.IsValid() && !solicitor.IsUnspecified()
	dstAddr := netip.MustParseAddr("ff02::1")
	if solicited {
		dstAddr = solicitor
	}
	dst := &unix.SockaddrInet6{Addr: dstAddr.As16(), ZoneId: uint32(c.ifIndex)}
	return unix.Sendto(c.fd, marshalNeighborAdvertisement(target, c.mac, solicited), 0, dst)
}
