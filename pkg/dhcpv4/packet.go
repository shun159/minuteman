package dhcpv4

import (
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// DHCP well-known UDP ports (RFC 2131 §4.1): the server listens on 67 and
// replies to the client's 68.
const (
	bootpServerPort uint16 = 67
	bootpClientPort uint16 = 68
)

// A DHCPv4 server can't use an ordinary UDP socket cleanly: it must reply to
// a client that has no IP address yet (and no ARP entry the kernel could
// resolve), honouring the client's broadcast flag, and it must know which
// LAN interface a broadcast arrived on. So, like pkg/ndproxy, it uses a
// cooked AF_PACKET socket (SOCK_DGRAM, payload starting at the IP header)
// bound to one interface: received frames are parsed as IPv4/UDP in Go
// (ParseRequest), and replies are built as raw IPv4+UDP (Frame) and sent
// with an explicit destination MAC (the client's chaddr, or broadcast) via
// sendto -- the kernel supplies the Ethernet header from the sockaddr_ll.
// A classic-BPF filter (Filter) keeps all non-DHCP traffic out of
// userspace. The socket itself is internal/dhcpv4server's.

// Filter is the classic-BPF program to attach to the packet socket:
// accept only IPv4/UDP packets whose destination port is 67 (the DHCP
// server port). Offsets are relative to the IPv4 header, since a cooked
// (SOCK_DGRAM) packet socket delivers from the network header on.
var Filter = []unix.SockFilter{
	{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},                               // IPv4 protocol
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.IPPROTO_UDP, Jf: 4},        // != UDP -> drop
	{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0},                              // X = IPv4 header length (4*(IHL))
	{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 2},                               // UDP destination port
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(bootpServerPort), Jf: 1}, // != 67 -> drop
	{Code: unix.BPF_RET | unix.BPF_K, K: 0xffff},                                        // accept
	{Code: unix.BPF_RET | unix.BPF_K, K: 0},                                             // drop
}

// ParseRequest parses packet, as the packet socket delivers it (from the
// IPv4 header on), as a DHCP request: ok is false for anything that is not
// IPv4/UDP to the DHCP server port carrying a valid DHCP message.
func ParseRequest(packet []byte) (msg *Message, ok bool) {
	payload, ok := parseUDPToBOOTP(packet)
	if !ok {
		return nil, false
	}
	msg, err := Parse(payload)
	if err != nil {
		return nil, false // slipped the filter but isn't valid DHCP
	}
	return msg, true
}

// Frame frames reply as IPv4+UDP from srcIP:67 to its destination's port
// 68 (see destination), and returns it with the link-layer address to send
// it to: the client's chaddr, or broadcast.
func Frame(srcIP netip.Addr, reply *Message) (frame []byte, dstMAC net.HardwareAddr) {
	dstIP, dstMAC := destination(reply)
	return buildFrame(srcIP, dstIP, reply.Marshal()), dstMAC
}

// parseUDPToBOOTP extracts the UDP payload of an IPv4/UDP packet destined
// for the DHCP server port, returning ok=false for anything else. The BPF
// filter already enforces this; the checks are repeated defensively (and to
// locate the variable-length IPv4 header and trim any Ethernet padding via
// the UDP length field).
func parseUDPToBOOTP(b []byte) (payload []byte, ok bool) {
	if len(b) < 20 || b[0]>>4 != 4 || b[9] != unix.IPPROTO_UDP {
		return nil, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl+8 {
		return nil, false
	}
	udp := b[ihl:]
	if getUint16(udp[2:]) != bootpServerPort {
		return nil, false
	}
	udpLen := int(getUint16(udp[4:]))
	if udpLen < 8 || udpLen > len(udp) {
		return nil, false
	}
	return udp[8:udpLen], true
}

// destination returns where a reply should be sent (RFC 2131 §4.1, for the
// directly-attached giaddr==0 case this server handles): broadcast if the
// client set the broadcast flag or this is a NAK (both set it), otherwise
// unicast to the assigned address at the client's own hardware address.
func destination(reply *Message) (netip.Addr, net.HardwareAddr) {
	if reply.Broadcast() {
		return netip.AddrFrom4([4]byte{255, 255, 255, 255}), net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
	dstIP := reply.YIAddr
	if !dstIP.Is4() || dstIP.IsUnspecified() {
		dstIP = reply.CIAddr // INFORM ACK: the client is already at ciaddr
	}
	return dstIP, reply.CHAddr
}

// buildFrame wraps payload in IPv4 (src->dst, TTL 64) and UDP (67->68)
// headers, computing both the mandatory IPv4 header checksum and the UDP
// checksum.
func buildFrame(src, dst netip.Addr, payload []byte) []byte {
	const ipHdr, udpHdr = 20, 8
	udpLen := udpHdr + len(payload)
	frame := make([]byte, ipHdr+udpLen)

	// IPv4 header.
	frame[0] = 0x45 // version 4, IHL 5 (no options)
	putUint16(frame[2:], uint16(ipHdr+udpLen))
	frame[8] = 64               // TTL
	frame[9] = unix.IPPROTO_UDP // protocol
	s4, d4 := src.As4(), dst.As4()
	copy(frame[12:16], s4[:])
	copy(frame[16:20], d4[:])
	putUint16(frame[10:], checksum(frame[:ipHdr]))

	// UDP header + payload.
	udp := frame[ipHdr:]
	putUint16(udp[0:], bootpServerPort)
	putUint16(udp[2:], bootpClientPort)
	putUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], payload)
	csum := udpChecksum(s4, d4, udp)
	if csum == 0 {
		csum = 0xffff // RFC 768: a computed checksum of zero is sent as all ones
	}
	putUint16(udp[6:], csum)

	return frame
}

// udpChecksum computes the UDP checksum over the IPv4 pseudo-header plus the
// UDP header (with its checksum field still zero) and payload.
func udpChecksum(src, dst [4]byte, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = unix.IPPROTO_UDP
	putUint16(pseudo[10:], uint16(len(udp)))
	copy(pseudo[12:], udp)
	return checksum(pseudo)
}

// checksum computes the 16-bit one's-complement checksum (RFC 1071) of b.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
