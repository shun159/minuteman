package ndproxy

import (
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
// userspace (NSFilter, ParseSolicitationPacket). Sending the proxy's
// Advertisements still goes through a raw ICMPv6 socket, which gets
// checksums computed by the kernel. The sockets are internal/ndppd's.

// ipv6HeaderBytes is the fixed IPv6 header size; NDP packets can't carry
// extension headers in practice (RFC 4861 requires hop limit 255 and no
// fragmentation), so the ICMPv6 message always starts right after it.
const ipv6HeaderBytes = 40

// NSFilter is the classic-BPF program to attach to the WAN packet socket:
// accept only IPv6 packets whose Next Header is ICMPv6, whose ICMPv6
// type is Neighbor Solicitation, and whose hop limit is 255 (RFC 4861
// §7.1.1's validity requirement, which also blocks off-link spoofing).
// Offsets are relative to the IPv6 header, since SOCK_DGRAM packet
// sockets deliver from the network header on.
var NSFilter = []unix.SockFilter{
	{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 6},                               // IPv6 Next Header
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.IPPROTO_ICMPV6, Jf: 3},     // != ICMPv6 -> drop
	{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: ipv6HeaderBytes},                 // ICMPv6 Type
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: icmpTypeNeighborSolicit, Jf: 1}, // != NS -> drop
	{Code: unix.BPF_RET | unix.BPF_K, K: 0xffff},                                        // accept
	{Code: unix.BPF_RET | unix.BPF_K, K: 0},                                             // drop
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

// ParseSolicitationPacket parses a full IPv6 packet, as the WAN packet
// socket delivers it, as a Neighbor Solicitation: its Target Address and
// IPv6 source (the unspecified address for a DAD probe). ok is false for
// anything else.
func ParseSolicitationPacket(b []byte) (target, source netip.Addr, ok bool) {
	m, ok := parseSolicitationPacket(b)
	return m.target, m.source, ok
}

// message is a received NDP message's Target Address and IPv6 source.
type message struct {
	target netip.Addr
	source netip.Addr
}
