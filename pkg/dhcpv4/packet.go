package dhcpv4

import (
	"fmt"
	"math/bits"
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
// bound to one interface: received frames are parsed as IPv4/UDP in Go, and
// replies are built as raw IPv4+UDP and sent with an explicit destination
// MAC (the client's chaddr, or broadcast) via sendto -- the kernel supplies
// the Ethernet header from the sockaddr_ll. A classic-BPF filter keeps all
// non-DHCP traffic out of userspace.

// packetConn receives and sends DHCPv4 on one interface. Close may be called
// from another goroutine to unblock a blocked recv.
type packetConn struct {
	fd      int
	ifindex int
	srcIP   netip.Addr // the server's own IPv4 on this link, used as the reply source
}

// dhcpFilter is the classic-BPF program attached to the packet socket:
// accept only IPv4/UDP packets whose destination port is 67 (the DHCP
// server port). Offsets are relative to the IPv4 header, since a cooked
// (SOCK_DGRAM) packet socket delivers from the network header on.
var dhcpFilter = []unix.SockFilter{
	{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},                               // IPv4 protocol
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.IPPROTO_UDP, Jf: 4},        // != UDP -> drop
	{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0},                              // X = IPv4 header length (4*(IHL))
	{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 2},                               // UDP destination port
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(bootpServerPort), Jf: 1}, // != 67 -> drop
	{Code: unix.BPF_RET | unix.BPF_K, K: 0xffff},                                        // accept
	{Code: unix.BPF_RET | unix.BPF_K, K: 0},                                             // drop
}

// listenPacket opens the DHCP packet socket on iface, with srcIP as the
// source address for replies sent through it.
func listenPacket(iface string, srcIP netip.Addr) (*packetConn, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("dhcpv4: looking up interface %s: %w", iface, err)
	}

	proto := bits.ReverseBytes16(unix.ETH_P_IP) // network byte order, as AF_PACKET requires
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return nil, fmt.Errorf("dhcpv4: opening packet socket: %w", err)
	}
	c := &packetConn{fd: fd, ifindex: ifi.Index, srcIP: srcIP}

	// Attach the filter before bind so no unfiltered packet is ever queued.
	prog := unix.SockFprog{Len: uint16(len(dhcpFilter)), Filter: &dhcpFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		c.Close()
		return nil, fmt.Errorf("dhcpv4: attaching DHCP filter on %s: %w", iface, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index}); err != nil {
		c.Close()
		return nil, fmt.Errorf("dhcpv4: binding packet socket to %s: %w", iface, err)
	}
	return c, nil
}

func (c *packetConn) Close() error { return unix.Close(c.fd) }

// recv blocks until a well-formed DHCP request arrives (skipping anything
// that slips through the filter but fails to parse as IPv4/UDP/DHCP) or the
// socket is closed, in which case it returns the read error.
func (c *packetConn) recv() (*Message, error) {
	buf := make([]byte, 1500)
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			return nil, err
		}
		payload, ok := parseUDPToBOOTP(buf[:n])
		if !ok {
			continue
		}
		msg, err := Parse(payload)
		if err != nil {
			continue // slipped the filter but isn't valid DHCP
		}
		return msg, nil
	}
}

// send transmits reply to dstMAC/dstIP: it frames reply as IPv4+UDP (source
// c.srcIP:67, destination dstIP:68) and hands it to the kernel with dstMAC
// as the link-layer destination.
func (c *packetConn) send(reply *Message, dstIP netip.Addr, dstMAC net.HardwareAddr) error {
	frame := buildFrame(c.srcIP, dstIP, reply.Marshal())
	sll := &unix.SockaddrLinklayer{
		Protocol: bits.ReverseBytes16(unix.ETH_P_IP),
		Ifindex:  c.ifindex,
		Halen:    uint8(len(dstMAC)),
	}
	copy(sll.Addr[:], dstMAC)
	return unix.Sendto(c.fd, frame, 0, sll)
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
