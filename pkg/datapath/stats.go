package datapath

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// statID mirrors bpf/datapath.bpf.c's enum stat_id. The BPF map only stores
// raw __u64 counters (no BTF enum type survives to the compiled object, see
// gen.go), so this order must be kept in sync with the C enum by hand.
type statID uint32

const (
	statPass statID = iota
	statDrop
	statAbort
	statEncap
	statDecap
	statMTUDrop
	statNoConfig
	statNoLANConfig
	statBypass
	statFIBSuccess
	statFIBNoNeigh
	statFIBFail
	statFIBWrongIf
	statDecapPass
	statDecapNotDSLite
	statDecapBadPacket
	statDecapSlow
	statRedirectWAN
	statRedirectLAN
	statICMPFragNeeded
	statIPv6Fwd
	statIPv6Pass
	statIPv6RSSRedirect
	statICMPRateLimited
	statAffinityInsert
	statAffinityInsertFail
	statAffinityPinned
	statEncapFragSlow
	statDecapFragSlow
	statDecapReasmPass
	statDecapMartian
	statMax
)

// Stats reads and sums the datapath's per-CPU counters across all CPUs.
func (l *Loader) Stats() (Stats, error) {
	return sumStats(l.objs.Stats)
}

// ReadPinnedStats reads the stats map a running minuteman pinned to bpffs
// (see pinStats), for out-of-band observers like the `minuteman stats`
// subcommand that have no Loader of their own.
func ReadPinnedStats() (Stats, error) {
	m, err := ebpf.LoadPinnedMap(statsPinPath, nil)
	if err != nil {
		return Stats{}, fmt.Errorf("opening pinned stats map %s (is minuteman running?): %w", statsPinPath, err)
	}
	defer m.Close()
	return sumStats(m)
}

// sumStats sums the per-CPU counters in a stats map handle across all CPUs.
func sumStats(m *ebpf.Map) (Stats, error) {
	var s Stats
	fields := [statMax]*uint64{
		statPass:            &s.Pass,
		statDrop:            &s.Drop,
		statAbort:           &s.Abort,
		statEncap:           &s.Encap,
		statDecap:           &s.Decap,
		statMTUDrop:         &s.MTUDrop,
		statNoConfig:        &s.NoConfig,
		statNoLANConfig:     &s.NoLANConfig,
		statBypass:          &s.Bypass,
		statFIBSuccess:      &s.FIBSuccess,
		statFIBNoNeigh:      &s.FIBNoNeigh,
		statFIBFail:         &s.FIBFail,
		statFIBWrongIf:      &s.FIBWrongIf,
		statDecapPass:       &s.DecapPass,
		statDecapNotDSLite:  &s.DecapNotDSLite,
		statDecapBadPacket:  &s.DecapBadPacket,
		statDecapSlow:       &s.DecapSlow,
		statRedirectWAN:     &s.RedirectWAN,
		statRedirectLAN:     &s.RedirectLAN,
		statICMPFragNeeded:  &s.ICMPFragNeeded,
		statIPv6Fwd:         &s.IPv6Fwd,
		statIPv6Pass:        &s.IPv6Pass,
		statIPv6RSSRedirect: &s.IPv6RSSRedirect,
		statICMPRateLimited: &s.ICMPRateLimited,

		statAffinityInsert:     &s.AffinityInsert,
		statAffinityInsertFail: &s.AffinityInsertFail,
		statAffinityPinned:     &s.AffinityPinned,

		statEncapFragSlow:  &s.EncapFragSlow,
		statDecapFragSlow:  &s.DecapFragSlow,
		statDecapReasmPass: &s.DecapReasmPass,
		statDecapMartian:   &s.DecapMartian,
	}

	for id, dst := range fields {
		key := uint32(id)
		var perCPU []uint64
		if err := m.Lookup(&key, &perCPU); err != nil {
			return Stats{}, fmt.Errorf("reading stat %d: %w", id, err)
		}
		for _, v := range perCPU {
			*dst += v
		}
	}

	return s, nil
}
