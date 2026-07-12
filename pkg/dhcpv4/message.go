// Package dhcpv4 implements the LAN-side DHCPv4 server a DS-Lite (RFC 6333)
// B4 element needs to hand its LAN clients private IPv4 addresses,
// default-gateway, DNS, and MTU configuration -- the counterpart to the
// WAN-side softwire that carries that IPv4 traffic. It is a server only
// (RFC 2131 §4.3's SELECTING/RENEWING handling), not a client, and covers
// exactly the directly-attached, single-subnet-per-interface case a home
// CPE serves: no BOOTP relay/giaddr forwarding, no multi-subnet shared
// networks, no persistence across restarts (an in-memory pool, like the
// rest of minuteman's state).
//
// Following the same split pkg/ndproxy uses, the wire codec (this file,
// options.go), the lease pool (lease.go), and the request→reply decision
// logic (handler.go) are pure and unit-tested, while the raw AF_PACKET
// socket I/O (packet.go) and the goroutine orchestration (server.go) are
// exercised by the netns rig instead.
package dhcpv4

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// BOOTP operation codes (RFC 2131 §2).
type OpCode uint8

const (
	OpBootRequest OpCode = 1 // client -> server
	OpBootReply   OpCode = 2 // server -> client
)

// hardwareTypeEthernet is the ARP hardware type (RFC 2131 §2, "htype")
// for 10/100/1000Mb Ethernet -- the only link type this CPE serves.
const hardwareTypeEthernet uint8 = 1

// bootpFixedLen is the size of the fixed BOOTP header preceding the options
// field (RFC 2131 §2: op..file, before the magic cookie).
const bootpFixedLen = 236

// magicCookie is the four-octet options-field prefix (RFC 2131 §3,
// "the first four octets ... 99, 130, 83 and 99") that marks the rest of
// the packet as DHCP (vs. plain BOOTP) options.
var magicCookie = [4]byte{0x63, 0x82, 0x53, 0x63}

// minMessageLen is the smallest DHCP payload this package emits. RFC 2131
// doesn't mandate a minimum, but BOOTP relays and some clients historically
// expect at least a 300-byte payload (RFC 951's fixed BOOTP size), so
// replies are zero-padded up to this length after the END option.
const minMessageLen = 300

// Message is a DHCPv4/BOOTP message (RFC 2131 §2). The four address fields
// are IPv4 netip.Addr (an invalid Addr encodes as 0.0.0.0). CHAddr holds
// the client hardware address (HLen bytes; 6 for Ethernet).
type Message struct {
	Op     OpCode
	HType  uint8
	HLen   uint8
	Hops   uint8
	XID    uint32
	Secs   uint16
	Flags  uint16
	CIAddr netip.Addr // client's current IP (bound state: RENEW/REBIND/INFORM)
	YIAddr netip.Addr // 'your' IP: the address being offered/assigned
	SIAddr netip.Addr // next-server IP
	GIAddr netip.Addr // relay agent IP (0.0.0.0 for a directly-attached client)
	CHAddr net.HardwareAddr
	SName  string
	File   string

	Options Options
}

// flagBroadcast is the high bit of the flags field (RFC 2131 §2, Figure 2):
// set by a client that cannot receive unicast IP before it's configured, so
// the server must broadcast the reply.
const flagBroadcast uint16 = 0x8000

// Broadcast reports whether the client set the broadcast flag.
func (m *Message) Broadcast() bool { return m.Flags&flagBroadcast != 0 }

// Marshal encodes m per RFC 2131 §2, appending the magic cookie, the
// options, an END option, and zero padding up to minMessageLen.
func (m *Message) Marshal() []byte {
	b := make([]byte, bootpFixedLen)
	b[0] = byte(m.Op)
	b[1] = m.HType
	b[2] = m.HLen
	b[3] = m.Hops
	putUint32(b[4:], m.XID)
	putUint16(b[8:], m.Secs)
	putUint16(b[10:], m.Flags)
	putAddr4(b[12:], m.CIAddr)
	putAddr4(b[16:], m.YIAddr)
	putAddr4(b[20:], m.SIAddr)
	putAddr4(b[24:], m.GIAddr)
	copy(b[28:44], m.CHAddr) // chaddr is 16 bytes; a 6-byte MAC leaves the rest zero
	copy(b[44:108], m.SName)
	copy(b[108:236], m.File)

	b = append(b, magicCookie[:]...)
	b = append(b, m.Options.Marshal()...)
	b = append(b, byte(OptEnd))
	for len(b) < minMessageLen {
		b = append(b, byte(OptPad))
	}
	return b
}

// Parse decodes a DHCPv4/BOOTP message per RFC 2131 §2.
func Parse(b []byte) (*Message, error) {
	if len(b) < bootpFixedLen+len(magicCookie) {
		return nil, fmt.Errorf("dhcpv4: message too short (%d bytes)", len(b))
	}
	if [4]byte(b[bootpFixedLen:bootpFixedLen+4]) != magicCookie {
		return nil, fmt.Errorf("dhcpv4: bad magic cookie")
	}

	m := &Message{
		Op:     OpCode(b[0]),
		HType:  b[1],
		HLen:   b[2],
		Hops:   b[3],
		XID:    getUint32(b[4:]),
		Secs:   getUint16(b[8:]),
		Flags:  getUint16(b[10:]),
		CIAddr: getAddr4(b[12:]),
		YIAddr: getAddr4(b[16:]),
		SIAddr: getAddr4(b[20:]),
		GIAddr: getAddr4(b[24:]),
		SName:  cstr(b[44:108]),
		File:   cstr(b[108:236]),
	}
	hlen := min(int(m.HLen), 16) // chaddr field is only 16 bytes; ignore an over-long HLen
	m.CHAddr = net.HardwareAddr(slices.Clone(b[28 : 28+hlen]))

	opts, err := parseOptions(b[bootpFixedLen+4:])
	if err != nil {
		return nil, fmt.Errorf("dhcpv4: parsing options: %w", err)
	}
	m.Options = opts
	return m, nil
}

func putUint16(b []byte, v uint16) { b[0], b[1] = byte(v>>8), byte(v) }
func getUint16(b []byte) uint16    { return uint16(b[0])<<8 | uint16(b[1]) }

func putUint32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}
func getUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// putAddr4 writes a's 4 IPv4 bytes into b, or four zero bytes (0.0.0.0) if
// a isn't a valid IPv4 address.
func putAddr4(b []byte, a netip.Addr) {
	if a.Is4() {
		v := a.As4()
		copy(b[:4], v[:])
	}
}

// getAddr4 reads a 4-byte IPv4 address.
func getAddr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b[:4])) }

// cstr trims a fixed-width NUL-padded BOOTP string field at its first NUL.
func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
