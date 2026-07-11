// Package routeradvert implements the subset of RFC 4861 (Neighbor
// Discovery for IP version 6) needed to act as an IPv6 router advertising a
// prefix for SLAAC: sending Router Advertisements (both periodic unsolicited
// and in response to inbound Router Solicitations) carrying a Prefix
// Information Option, plus -- for a CPE's own WAN-facing host role -- sending
// Router Solicitations upstream (SolicitRouters). It does not implement any
// other NDP message type or router behavior (no Neighbor
// Solicitation/Advertisement, no redirects).
package routeradvert

import (
	"encoding/binary"
	"time"
)

// ICMPv6 types used by this package (RFC 4861 §4.1/§4.2).
const (
	icmpTypeRouterSolicit uint8 = 133
	icmpTypeRouterAdvert  uint8 = 134
)

// icmpv6FixedHeaderBytes is the ICMPv6 Type/Code/Checksum common header
// (RFC 4443 §2.1) every message starts with.
const icmpv6FixedHeaderBytes = 4

// raFixedFieldsBytes is the length of a Router Advertisement's fixed fields
// after the ICMPv6 Type/Code/Checksum (RFC 4861 §4.2): Cur Hop Limit (1),
// M/O flags + Reserved (1), Router Lifetime (2), Reachable Time (4),
// Retrans Timer (4).
const raFixedFieldsBytes = 1 + 1 + 2 + 4 + 4

// maxRouterLifetime is the largest value RouterLifetime's wire field (a
// 16-bit number of seconds) can represent (RFC 4861 §4.2).
const maxRouterLifetime = 65535 * time.Second

// RouterAdvertisement is a Router Advertisement message (RFC 4861 §4.2).
// The Checksum field is left zero on Marshal: for an IPPROTO_ICMPV6 raw
// socket, the kernel always computes and fills in the ICMPv6 checksum
// (including the IPv6 pseudo-header) on send, per RFC 3542 §3.1 -- unlike
// raw IPv4/ICMPv4 sockets, no manual checksum computation is needed or
// possible here.
type RouterAdvertisement struct {
	// CurHopLimit is advertised to hosts as the Hop Limit to use for
	// outgoing packets; 0 means "unspecified, use your own default".
	CurHopLimit uint8
	// RouterLifetime is how long this router should be used as a default
	// router, truncated to whole seconds and saturating at
	// maxRouterLifetime; 0 means "not a default router" (RFC 4861 §6.2.5's
	// graceful-shutdown value).
	RouterLifetime time.Duration
	// ReachableTime and RetransTimer are advertised to hosts for their own
	// Neighbor Unreachability Detection, truncated to whole milliseconds;
	// 0 means "unspecified, use your own default" for both (RFC 4861
	// §6.2.1's defaults).
	ReachableTime, RetransTimer time.Duration
	Options                     Options
}

// Marshal encodes ra as a complete ICMPv6 Router Advertisement message
// (RFC 4861 §4.2), Checksum left zero (see RouterAdvertisement's doc
// comment).
func (ra *RouterAdvertisement) Marshal() []byte {
	optBytes := ra.Options.Marshal()
	b := make([]byte, icmpv6FixedHeaderBytes+raFixedFieldsBytes+len(optBytes))

	lifetime := min(ra.RouterLifetime, maxRouterLifetime)

	b[0] = icmpTypeRouterAdvert
	// b[1] Code = 0, b[2:4] Checksum left zero (kernel-computed).
	b[4] = ra.CurHopLimit
	// b[5] M/O flags + Reserved: always 0 (no stateful DHCPv6 needed).
	binary.BigEndian.PutUint16(b[6:8], uint16(lifetime/time.Second))
	binary.BigEndian.PutUint32(b[8:12], uint32(ra.ReachableTime/time.Millisecond))
	binary.BigEndian.PutUint32(b[12:16], uint32(ra.RetransTimer/time.Millisecond))
	copy(b[16:], optBytes)

	return b
}

// isRouterSolicitation reports whether b (an ICMPv6 message payload, as
// delivered by a raw IPPROTO_ICMPV6 socket without an IPv6 header) is a
// Router Solicitation (RFC 4861 §4.1). Only the ICMPv6 Type is checked --
// this package never needs to decode a Solicitation's body, since an RS
// carries nothing it needs (its optional Source Link-Layer Address option
// is solely an optimization for the router's own Neighbor Cache, which this
// package doesn't maintain).
func isRouterSolicitation(b []byte) bool {
	return len(b) >= 1 && b[0] == icmpTypeRouterSolicit
}
