package ndproxy

import (
	"fmt"
	"math/bits"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// The WAN side can't receive Neighbor Solicitations through a raw
// IPPROTO_ICMPV6 socket: an NS is sent to the target's Solicited-Node
// multicast group (a different group per target address), and the
// kernel's IPv6 input path drops multicast packets for groups the host
// hasn't joined before raw sockets ever see them -- there's no way to
// join every possible group ahead of time, and ALLMULTI only opens the
// L2 filter, not the IPv6 membership check. So NS reception uses an
// AF_PACKET socket instead (the same approach ndppd takes): cooked
// (SOCK_DGRAM, so payload starts at the IPv6 header), bound to the
// interface with an ALLMULTI membership, and with a classic-BPF filter
// attached so only ICMPv6 Neighbor Solicitations ever cross into
// userspace. Sending the proxy's Advertisements still goes through a
// raw ICMPv6 socket (conn.go), which gets checksums computed by the
// kernel.

// ipv6HeaderBytes is the fixed IPv6 header size; NDP packets can't carry
// extension headers in practice (RFC 4861 requires hop limit 255 and no
// fragmentation), so the ICMPv6 message always starts right after it.
const ipv6HeaderBytes = 40

// nsFilter is the classic-BPF program attached to the WAN packet socket:
// accept only IPv6 packets whose Next Header is ICMPv6, whose ICMPv6
// type is Neighbor Solicitation, and whose hop limit is 255 (RFC 4861
// §7.1.1's validity requirement, which also blocks off-link spoofing).
// Offsets are relative to the IPv6 header, since SOCK_DGRAM packet
// sockets deliver from the network header on.
var nsFilter = []unix.SockFilter{
	{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 6},                               // IPv6 Next Header
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.IPPROTO_ICMPV6, Jf: 3},     // != ICMPv6 -> drop
	{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: ipv6HeaderBytes},                 // ICMPv6 Type
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: icmpTypeNeighborSolicit, Jf: 1}, // != NS -> drop
	{Code: unix.BPF_RET | unix.BPF_K, K: 0xffff},                                        // accept
	{Code: unix.BPF_RET | unix.BPF_K, K: 0},                                             // drop
}

// packetConn receives Neighbor Solicitations on one interface via an
// AF_PACKET socket (see the comment above). Close may be called from
// another goroutine to unblock a blocked reader.
type packetConn struct {
	fd int
}

// listenPacket opens the NS-receiving packet socket on iface.
func listenPacket(iface string) (*packetConn, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("ndproxy: looking up interface %s: %w", iface, err)
	}

	// Protocol ETH_P_IPV6 in network byte order, as AF_PACKET requires.
	proto := bits.ReverseBytes16(unix.ETH_P_IPV6)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return nil, fmt.Errorf("ndproxy: opening packet socket: %w", err)
	}
	c := &packetConn{fd: fd}

	// Attach the filter before bind so no unfiltered packet is ever
	// queued (a socket receives from creation, filter or not).
	prog := unix.SockFprog{Len: uint16(len(nsFilter)), Filter: &nsFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		c.Close()
		return nil, fmt.Errorf("ndproxy: attaching NS filter on %s: %w", iface, err)
	}

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index}); err != nil {
		c.Close()
		return nil, fmt.Errorf("ndproxy: binding packet socket to %s: %w", iface, err)
	}

	// All-multicast membership, so Solicited-Node multicast frames for
	// arbitrary (LAN-side) target addresses pass the NIC's L2 filter at
	// all. Held on this socket, the kernel drops it automatically on
	// close.
	mreq := &unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_ALLMULTI}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq); err != nil {
		c.Close()
		return nil, fmt.Errorf("ndproxy: enabling all-multicast on %s: %w", iface, err)
	}

	return c, nil
}

func (c *packetConn) Close() error {
	return unix.Close(c.fd)
}

// readSolicitations reads Neighbor Solicitations into ch until the
// socket is closed, then closes ch. Sends never block: if ch is full
// the solicitation is dropped -- NDP retransmits, so a dropped NS only
// delays resolution by a retransmission interval.
func (c *packetConn) readSolicitations(ch chan<- message) {
	defer close(ch)
	buf := make([]byte, 1500)
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			return
		}
		msg, ok := parseSolicitationPacket(buf[:n])
		if !ok {
			continue
		}
		select {
		case ch <- msg:
		default:
		}
	}
}

// parseSolicitationPacket parses a full IPv6 packet (as delivered by the
// cooked packet socket) as a Neighbor Solicitation, returning its Target
// Address and IPv6 source address. The BPF filter has already checked
// the Next Header and ICMPv6 Type; this re-validates defensively and
// checks the pieces cBPF didn't (version, code, length).
func parseSolicitationPacket(b []byte) (message, bool) {
	if len(b) < ipv6HeaderBytes+icmpv6FixedHeaderBytes+nsNAFixedFieldsBytes {
		return message{}, false
	}
	if b[0]>>4 != 6 || b[6] != unix.IPPROTO_ICMPV6 || b[7] != 255 {
		return message{}, false
	}
	icmp := b[ipv6HeaderBytes:]
	if icmp[0] != icmpTypeNeighborSolicit || icmp[1] != 0 {
		return message{}, false
	}
	source, _ := netip.AddrFromSlice(b[8:24])
	target, _ := netip.AddrFromSlice(icmp[icmpv6FixedHeaderBytes+4 : icmpv6FixedHeaderBytes+4+16])
	return message{target: target, source: source}, true
}
