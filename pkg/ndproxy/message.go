// Package ndproxy implements the subset of RFC 4389 (Neighbor Discovery
// Proxy) a CPE needs when the ISP hands out a single on-link /64 on the
// WAN with no prefix delegation: answering Neighbor Solicitations on the
// WAN link on behalf of hosts that live behind the CPE on a LAN link, so
// upstream traffic for them resolves to the CPE's own MAC and gets
// forwarded.
//
// Instead of passively snooping LAN NS/NA traffic to learn which
// addresses exist (which needs ALLMULTI on every LAN and trusts stale
// state), the proxy actively verifies: a WAN-side NS for an unknown
// target triggers an NS probe on the LAN side, and only a real NA reply
// makes the proxy answer upstream and (via the OnActive callback) get a
// host route installed. This is the same shape ndppd's "auto" mode uses,
// and it guarantees the WAN-side proxy replies only for hosts that
// actually exist right now.
//
// Deliberate non-goals, vs. full RFC 4389: no cross-link DAD proxying
// (the odds of an address collision between WAN and LAN hosts within one
// /64 of SLAAC addresses are negligible), no RA/Redirect proxying (the
// caller re-advertises the WAN prefix on the LAN itself, with the
// on-link flag cleared so LAN hosts route everything through the CPE and
// LAN-side NS proxying is never needed), and no proxy-loop detection (a
// second ND proxy on the LAN is out of scope).
package ndproxy

import (
	"fmt"
	"net"
	"net/netip"
)

// ICMPv6 types used by this package (RFC 4861 §4.3/§4.4).
const (
	icmpTypeNeighborSolicit = 135
	icmpTypeNeighborAdvert  = 136
)

// icmpv6FixedHeaderBytes is the ICMPv6 Type/Code/Checksum common header
// (RFC 4443 §2.1); nsNAFixedFieldsBytes the Reserved/Flags word plus
// Target Address both NS and NA carry after it (RFC 4861 §4.3/§4.4).
const (
	icmpv6FixedHeaderBytes = 4
	nsNAFixedFieldsBytes   = 4 + 16
)

// NA flag bits (RFC 4861 §4.4), in the first byte after the ICMPv6 header.
const (
	naFlagRouter    = 0x80
	naFlagSolicited = 0x40
	naFlagOverride  = 0x20
)

// NDP option types used by this package (RFC 4861 §4.6.1).
const (
	optSourceLinkLayerAddress = 1
	optTargetLinkLayerAddress = 2
)

// parseTarget extracts the Target Address from an NS or NA payload (as
// delivered by a raw IPPROTO_ICMPV6 socket, without an IPv6 header),
// verifying the expected ICMPv6 type. Options are ignored: the proxy
// never needs a peer's link-layer address (it replies from and probes
// via its own interfaces, and the kernel's own neighbor cache handles
// actual forwarding).
func parseTarget(b []byte, wantType uint8) (netip.Addr, error) {
	if len(b) < icmpv6FixedHeaderBytes+nsNAFixedFieldsBytes {
		return netip.Addr{}, fmt.Errorf("ndproxy: message too short (%d bytes)", len(b))
	}
	if b[0] != wantType {
		return netip.Addr{}, fmt.Errorf("ndproxy: ICMPv6 type %d, want %d", b[0], wantType)
	}
	target, _ := netip.AddrFromSlice(b[icmpv6FixedHeaderBytes+4 : icmpv6FixedHeaderBytes+4+16])
	return target, nil
}

// marshalNeighborSolicitation encodes a Neighbor Solicitation for target
// (RFC 4861 §4.3) carrying a Source Link-Layer Address option for srcMAC
// (§4.3: MUST be included on multicast solicitations, which the proxy's
// probes always are). Checksum left zero: the kernel computes it on send
// for IPPROTO_ICMPV6 raw sockets, same as pkg/routeradvert's messages.
func marshalNeighborSolicitation(target netip.Addr, srcMAC net.HardwareAddr) []byte {
	b := make([]byte, icmpv6FixedHeaderBytes+nsNAFixedFieldsBytes+linkLayerOptionBytes(srcMAC))
	b[0] = icmpTypeNeighborSolicit
	// b[1] Code = 0, b[2:4] Checksum (kernel), b[4:8] Reserved: all zero.
	t := target.As16()
	copy(b[icmpv6FixedHeaderBytes+4:], t[:])
	putLinkLayerOption(b[icmpv6FixedHeaderBytes+nsNAFixedFieldsBytes:], optSourceLinkLayerAddress, srcMAC)
	return b
}

// marshalNeighborAdvertisement encodes the proxy's Neighbor Advertisement
// for target (RFC 4861 §4.4), advertising the proxy's own tgtMAC as the
// Target Link-Layer Address so the solicitor sends target's traffic to
// the proxy. Per RFC 4389 §4.1.3, a proxied advertisement keeps the
// Override flag cleared (so a real owner's own advertisement always
// wins) and, since the proxied nodes here are plain LAN hosts, the
// Router flag too; Solicited is set when answering a directed
// solicitation (one whose source wasn't the unspecified address).
func marshalNeighborAdvertisement(target netip.Addr, tgtMAC net.HardwareAddr, solicited bool) []byte {
	b := make([]byte, icmpv6FixedHeaderBytes+nsNAFixedFieldsBytes+linkLayerOptionBytes(tgtMAC))
	b[0] = icmpTypeNeighborAdvert
	if solicited {
		b[4] = naFlagSolicited
	}
	t := target.As16()
	copy(b[icmpv6FixedHeaderBytes+4:], t[:])
	putLinkLayerOption(b[icmpv6FixedHeaderBytes+nsNAFixedFieldsBytes:], optTargetLinkLayerAddress, tgtMAC)
	return b
}

// linkLayerOptionBytes is the encoded size of a Source/Target Link-Layer
// Address option for mac, rounded up to RFC 4861 §4.6's 8-byte option
// units (exactly one unit for the 6-byte MACs of Ethernet-like links).
func linkLayerOptionBytes(mac net.HardwareAddr) int {
	return (2 + len(mac) + 7) / 8 * 8
}

// putLinkLayerOption writes a Source/Target Link-Layer Address option
// (RFC 4861 §4.6.1) for mac into b, which must be at least
// linkLayerOptionBytes(mac) long.
func putLinkLayerOption(b []byte, optType uint8, mac net.HardwareAddr) {
	b[0] = optType
	b[1] = uint8(linkLayerOptionBytes(mac) / 8)
	copy(b[2:], mac)
}

// solicitedNodeMulticast returns addr's Solicited-Node multicast address,
// ff02::1:ffXX:XXXX with the low 24 bits copied from addr (RFC 4291
// §2.7.1) -- the group a Neighbor Solicitation for addr is sent to.
func solicitedNodeMulticast(addr netip.Addr) netip.Addr {
	a := addr.As16()
	return netip.AddrFrom16([16]byte{
		0: 0xff, 1: 0x02,
		11: 0x01, 12: 0xff,
		13: a[13], 14: a[14], 15: a[15],
	})
}
