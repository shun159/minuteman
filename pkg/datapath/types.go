package datapath

import (
	"net"
	"net/netip"
)

// B4Config is the DS-Lite (RFC 6333) B4 element configuration: the IPv6
// softwire between this gateway (B4Addr) and the AFTR (AFTRAddr) that
// IPv4 traffic is tunneled through (IPv4-in-IPv6, next header IPPROTO_IPIP).
type B4Config struct {
	B4Addr   netip.Addr // our IPv6 source address for the softwire
	AFTRAddr netip.Addr // the AFTR's IPv6 address

	// SrcMAC/DstMAC are used on the WAN side only as a fallback when
	// bpf_fib_lookup can't resolve a next-hop MAC (e.g. no neighbor entry).
	SrcMAC net.HardwareAddr
	DstMAC net.HardwareAddr

	// WANIfindex is the expected egress interface toward the AFTR; FIB
	// lookups that resolve to a different interface are rejected.
	WANIfindex uint32
}

// LANConfig is the per-LAN-interface configuration keyed by interface index.
type LANConfig struct {
	// GatewayIP is this gateway's own IPv4 address on the LAN interface;
	// packets addressed to it bypass DS-Lite encapsulation.
	GatewayIP netip.Addr
	InnerMTU  uint16
}

// Stats mirrors the datapath's per-CPU counters (bpf/datapath.bpf.c's
// enum stat_id), summed across all CPUs. Field order must stay in sync with
// that enum.
type Stats struct {
	Pass            uint64
	Drop            uint64
	Abort           uint64
	Encap           uint64
	Decap           uint64
	MTUDrop         uint64
	NoConfig        uint64
	NoLANConfig     uint64
	Bypass          uint64
	FIBSuccess      uint64
	FIBNoNeigh      uint64
	FIBFail         uint64
	FIBWrongIf      uint64
	DecapPass       uint64
	DecapNotDSLite  uint64
	DecapBadPacket  uint64
	DecapSlow       uint64
	RedirectWAN     uint64
	RedirectLAN     uint64
	ICMPFragNeeded  uint64
	IPv6Fwd         uint64
	IPv6Pass        uint64
	IPv6RSSRedirect uint64
	ICMPRateLimited uint64

	// AFTR-migration flow affinity (see bpf/datapath.bpf.c's PRIMING/DRAINING).
	//
	// AffinityInsert counts recording operations, not distinct flows: two CPUs
	// racing to record the same flow both count (they write the same value, so
	// it is only the tally that is approximate).
	//
	// AffinityInsertFail means the table is genuinely full -- the datapath
	// records with BPF_ANY precisely so a duplicate-insert race between CPUs
	// can't be mistaken for a failure. A migration must be abandoned rather
	// than cut over while this is rising: an unrecorded flow may predate the
	// switch, and would be moved to an AFTR holding no state for it.
	AffinityInsert     uint64
	AffinityInsertFail uint64
	AffinityPinned     uint64 // packets held on the old AFTR during DRAINING
}
