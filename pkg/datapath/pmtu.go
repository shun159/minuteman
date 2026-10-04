package datapath

import (
	"fmt"
	"time"
)

// TunnelPMTUExpiry is how long a softwire path MTU learned from an ICMPv6
// Packet Too Big stays in force, mirroring TUNNEL_PMTU_EXPIRY_NS in
// bpf/datapath.bpf.c. Both sides age readings out on the same clock: the
// datapath so an oversized packet stops being held back once the narrow path
// is gone, this package so the fragment size goes back to the WAN device's own
// MTU at the same moment.
const TunnelPMTUExpiry = 10 * time.Minute

// TunnelPMTU reports the smallest softwire path MTU the datapath has learned
// and not yet aged out, across every next_hop slot. ok is false when nothing
// has been learned -- the WAN device's MTU is then the only constraint.
//
// The minimum across slots is deliberate: the two slots hold the old and new
// AFTR during a migration, both carrying traffic, and the fragment size the
// caller derives from this is a single datapath-wide value. Taking the smaller
// costs a fragment or two on the wider path and keeps the narrower one working.
func (l *Loader) TunnelPMTU() (mtu uint32, ok bool) {
	now, err := monotonicNanos()
	if err != nil {
		return 0, false
	}

	for slot := uint32(0); slot < numNextHops; slot++ {
		var v bpfTunnelPmtu
		if err := l.objs.TunnelPmtus.Lookup(&slot, &v); err != nil {
			continue
		}
		if v.UpdatedNs == 0 || v.Mtu == 0 {
			continue
		}
		if now-v.UpdatedNs > uint64(TunnelPMTUExpiry) {
			continue
		}
		if !ok || v.Mtu < mtu {
			mtu, ok = v.Mtu, true
		}
	}
	return mtu, ok
}

// clearTunnelPMTU forgets whatever path MTU was learned for a next_hop slot,
// called whenever that slot's endpoint pair changes (see writeNextHop /
// clearNextHop). Without it a slot recycled by an AFTR migration or a dynamic-B4
// switch would inherit the previous softwire's reading, and TunnelPMTU -- which
// takes the minimum across slots -- would go on reporting a retired path's MTU
// until it aged out on its own.
func (l *Loader) clearTunnelPMTU(slot uint32) error {
	var zero bpfTunnelPmtu
	if err := l.objs.TunnelPmtus.Put(&slot, &zero); err != nil {
		return fmt.Errorf("clearing tunnel PMTU slot %d: %w", slot, err)
	}
	return nil
}

// SetSoftwireMTU updates what the datapath derives from the softwire MTU -- the
// WAN device's own MTU normally, or the smaller path MTU learned from an ICMPv6
// Packet Too Big (see TunnelPMTU): the in-XDP fragmenter's per-fragment payload
// size (b4_config.frag_unit) and, when the caller asked for TCPMSSClampAuto, the
// TCP MSS clamp. Everything else in b4_config is preserved.
//
// These are the only fields of b4_config written after startup. The datapath
// reads the struct field by field rather than as a snapshot, so a packet in
// flight can read a new value beside the old value of another field; that is
// harmless here because the two that move are read independently of everything
// else. The encap stage snapshots frag_unit into each clone, so companion
// stages never read a different unit for the same datagram when this update
// happens between their executions.
func (l *Loader) SetSoftwireMTU(mtu int) error {
	key := uint32(0)
	var val bpfB4Config
	if err := l.objs.B4ConfigMap.Lookup(&key, &val); err != nil {
		return fmt.Errorf("reading B4 config: %w", err)
	}

	val.FragUnit = softwireFragUnit(mtu)
	if l.mssClampAuto {
		val.MssClamp = autoTCPMSSClamp(mtu)
	}

	if err := l.objs.B4ConfigMap.Put(&key, &val); err != nil {
		return fmt.Errorf("setting softwire MTU %d: %w", mtu, err)
	}
	return nil
}
