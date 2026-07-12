package routeradvert

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"
)

// NDP option types this package builds (RFC 4861 §4.6, RFC 8106 §5.1).
const (
	optSourceLinkLayerAddress uint8 = 1  // §4.6.1
	optPrefixInformation      uint8 = 3  // §4.6.2
	optRecursiveDNSServer     uint8 = 25 // RFC 8106 §5.1
)

// optionUnitBytes is the unit NDP option Length fields are expressed in
// (RFC 4861 §4.6: "8-byte boundaries").
const optionUnitBytes = 8

// Options is a sequence of already-encoded NDP options (RFC 4861 §4.6),
// each a byte slice built by one of this file's New* functions.
type Options [][]byte

// Marshal concatenates every option back-to-back.
func (o Options) Marshal() []byte {
	n := 0
	for _, opt := range o {
		n += len(opt)
	}
	b := make([]byte, 0, n)
	for _, opt := range o {
		b = append(b, opt...)
	}
	return b
}

// PrefixInformation describes one Prefix Information Option (RFC 4861
// §4.6.2): the prefix a router advertises for on-link determination and/or
// stateless address autoconfiguration.
type PrefixInformation struct {
	Prefix            netip.Prefix
	OnLink            bool // L flag: usable for on-link determination
	Autonomous        bool // A flag: usable for SLAAC
	ValidLifetime     time.Duration
	PreferredLifetime time.Duration
}

// NewPrefixInformation builds a complete 32-byte Prefix Information Option
// (RFC 4861 §4.6.2). ValidLifetime/PreferredLifetime are truncated to whole
// seconds; the option's own Reserved fields are left zero.
func NewPrefixInformation(p PrefixInformation) []byte {
	const lengthUnits = 4 // 32 bytes / optionUnitBytes
	b := make([]byte, lengthUnits*optionUnitBytes)

	b[0] = optPrefixInformation
	b[1] = lengthUnits
	b[2] = uint8(p.Prefix.Bits())

	var flags uint8
	if p.OnLink {
		flags |= 0x80
	}
	if p.Autonomous {
		flags |= 0x40
	}
	b[3] = flags

	binary.BigEndian.PutUint32(b[4:8], uint32(p.ValidLifetime/time.Second))
	binary.BigEndian.PutUint32(b[8:12], uint32(p.PreferredLifetime/time.Second))
	// b[12:16] Reserved2 left zero.
	addr := p.Prefix.Addr().As16()
	copy(b[16:32], addr[:])

	return b
}

// NewSourceLinkLayerAddress builds a Source Link-Layer Address option (RFC
// 4861 §4.6.1) carrying mac. Routers SHOULD include this in every RA
// (§6.2.3) so hosts don't need a separate Neighbor Solicitation/
// Advertisement exchange just to learn it.
func NewSourceLinkLayerAddress(mac net.HardwareAddr) []byte {
	b := make([]byte, optionUnitBytes)
	b[0] = optSourceLinkLayerAddress
	b[1] = 1 // 8 bytes / optionUnitBytes
	copy(b[2:], mac)
	return b
}

// NewRDNSS builds a Recursive DNS Server option (RFC 8106 §5.1) listing
// servers, valid for lifetime (truncated to whole seconds). RFC 7084 §L-4
// requires an IPv6-only SLAAC LAN client be given a DNS server some way; this
// is the RA-carried way (the alternative, DHCPv6 stateless service, isn't
// something this project's LAN side runs). Per RFC 8106 §5.1 the address
// list needn't be global -- the router's own link-local address is
// explicitly permitted, which is what this project's callers use, so RDNSS
// composes with either WAN provisioning model (DHCPv6-PD's distinct
// delegated prefix or NDProxy's shared one) without depending on which one
// is active.
func NewRDNSS(servers []netip.Addr, lifetime time.Duration) []byte {
	const lengthUnits = 1 // header (8 bytes) / optionUnitBytes, before addresses
	b := make([]byte, (lengthUnits+2*len(servers))*optionUnitBytes)

	b[0] = optRecursiveDNSServer
	b[1] = uint8(lengthUnits + 2*len(servers))
	// b[2:4] Reserved left zero.
	binary.BigEndian.PutUint32(b[4:8], uint32(lifetime/time.Second))

	for i, s := range servers {
		addr := s.As16()
		copy(b[8+i*16:8+(i+1)*16], addr[:])
	}

	return b
}
