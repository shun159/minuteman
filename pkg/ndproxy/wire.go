package ndproxy

import (
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// ICMP6Filter is Linux's ICMP6_FILTER sockopt name (<netinet/icmp6.h>), not
// exported by golang.org/x/sys/unix for Linux -- vendored here the same way
// pkg/routeradvert vendors it.
const ICMP6Filter = 1

// allNodes is the link-scope All-Nodes multicast address.
var allNodes = netip.MustParseAddr("ff02::1")

// ICMPv6Filter is an ICMP6_FILTER passing only ICMPv6 messages of types,
// none if there are none: a LAN-side socket passes Neighbor
// Advertisements (AdvertisementType), the WAN-side sending one nothing.
func ICMPv6Filter(types ...uint8) *unix.ICMPv6Filter {
	var filt unix.ICMPv6Filter
	for i := range filt.Data {
		filt.Data[i] = 0xffffffff // block everything...
	}
	for _, t := range types {
		filt.Data[t/32] &^= 1 << (t % 32) // ...except these
	}
	return &filt
}

// AdvertisementType is the ICMPv6 type of a Neighbor Advertisement.
const AdvertisementType uint8 = icmpTypeNeighborAdvert

// Solicitation is the proxy's Neighbor Solicitation probe for target, from
// an interface with srcMAC, and where to send it: target's Solicited-Node
// multicast group.
func Solicitation(target netip.Addr, srcMAC net.HardwareAddr) (msg []byte, dst netip.Addr) {
	return marshalNeighborSolicitation(target, srcMAC), solicitedNodeMulticast(target)
}

// Advertisement is the proxy's Neighbor Advertisement for target, answering
// solicitor with the proxy's own tgtMAC, and where to send it, per RFC 4861
// §7.2.4's destination rules: unicast back to the solicitor, or -- answering
// a DAD-style solicitation from the unspecified address -- to the All-Nodes
// group, unsolicited.
func Advertisement(target, solicitor netip.Addr, tgtMAC net.HardwareAddr) (msg []byte, dst netip.Addr) {
	solicited := solicitor.IsValid() && !solicitor.IsUnspecified()
	dst = allNodes
	if solicited {
		dst = solicitor
	}
	return marshalNeighborAdvertisement(target, tgtMAC, solicited), dst
}

// ParseAdvertisement returns the Target Address of a Neighbor Advertisement
// as a raw ICMPv6 socket delivers it (no IPv6 header); ok is false for
// anything else.
func ParseAdvertisement(b []byte) (target netip.Addr, ok bool) {
	target, err := parseTarget(b, icmpTypeNeighborAdvert)
	return target, err == nil
}
