package datapath

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// registerTxPort makes ifindex a valid bpf_redirect_map() target by adding
// a self-mapped entry (ifindex -> ifindex) to the tx_ports DEVMAP_HASH.
func (l *Loader) registerTxPort(ifindex uint32) error {
	if err := l.objs.TxPorts.Put(&ifindex, &ifindex); err != nil {
		return fmt.Errorf("registering tx port for ifindex %d: %w", ifindex, err)
	}
	return nil
}

// numNextHops is the number of next-hop (softwire endpoint) slots the
// datapath holds, matching NUM_NEXT_HOPS in bpf/datapath.bpf.c. Two is
// enough for one live AFTR switch at a time: the outgoing AFTR in one slot,
// the incoming one in the other.
const numNextHops = 2

// validateSoftwireAddrs checks that both softwire endpoints are IPv6, so
// callers reject a bad address before mutating any datapath state.
func validateSoftwireAddrs(b4, aftr netip.Addr) error {
	if !b4.Is6() || b4.Is4In6() {
		return fmt.Errorf("B4 address must be IPv6, got %s", b4)
	}
	if !aftr.Is6() || aftr.Is4In6() {
		return fmt.Errorf("AFTR address must be IPv6, got %s", aftr)
	}
	return nil
}

// SetB4Config installs the DS-Lite softwire configuration used by both the
// encap and decap programs: the WAN-global fields (MACs, ifindex) plus the
// initial AFTR pair, which it places in next-hop slot 0 and makes active. It
// is the single-AFTR startup path; live AFTR re-discovery uses SwitchAFTR.
// Both endpoints are validated before any map is written, so a bad address
// leaves the datapath untouched.
func (l *Loader) SetB4Config(cfg B4Config) error {
	if err := validateSoftwireAddrs(cfg.B4Addr, cfg.AFTRAddr); err != nil {
		return err
	}

	var val bpfB4Config
	copy(val.SrcMac[:], cfg.SrcMAC)
	copy(val.DstMac[:], cfg.DstMAC)
	val.WanIfindex = cfg.WANIfindex
	// val.B4Addr/AftrAddr are intentionally left zero: the datapath reads
	// the softwire addresses from the active next_hop slot, not from here
	// (see resolve_softwire in bpf/datapath.bpf.c).

	key := uint32(0)
	if err := l.objs.B4ConfigMap.Put(&key, &val); err != nil {
		return fmt.Errorf("setting B4 config: %w", err)
	}

	if err := l.writeNextHop(0, cfg.B4Addr, cfg.AFTRAddr); err != nil {
		return err
	}
	if err := l.writeCtrl(migrationCtrl{activeSlot: 0, oldSlot: 0, state: migSteady}); err != nil {
		return err
	}

	return l.registerTxPort(cfg.WANIfindex)
}

// SwitchAFTR moves the live softwire endpoint pair to (b4, aftr): it writes the
// free slot in full, then points the control word at it. The slot the datapath
// is resolving is never mutated, so it can never read a half-updated endpoint
// (a next_hop is copied into place on update, with no RCU replacement — see the
// note on struct next_hop in bpf/datapath.bpf.c), and the sequence is encoded
// here so a caller can't reintroduce that hazard by driving the slots directly.
// The replaced endpoint is left valid in its slot, so decap keeps accepting its
// in-flight return traffic until a later switch recycles that slot.
//
// This switch is immediate: in-flight flows are moved to the new AFTR, which has
// no NAT state for them, and break. That is correct when they are unrecoverable
// anyway (a changed B4 address invalidates the AFTR's state), and is the only
// behaviour available until graceful migration lands.
func (l *Loader) SwitchAFTR(b4, aftr netip.Addr) error {
	if err := validateSoftwireAddrs(b4, aftr); err != nil {
		return err
	}

	c, err := l.readCtrl()
	if err != nil {
		return err
	}
	free := (c.activeSlot + 1) % numNextHops

	if err := l.writeNextHop(free, b4, aftr); err != nil {
		return err
	}
	return l.writeCtrl(migrationCtrl{
		activeSlot: free,
		oldSlot:    free,
		state:      migSteady,
		epoch:      c.epoch,
	})
}

// slotIsLive reports whether the datapath can currently resolve slot for
// encapsulation. Today that is just the active slot; graceful migration will
// add the old slot while flows are still pinned to it. A slot that isn't valid
// yet can't be resolved whatever the control word says (resolve_softwire checks
// nh->valid), so the initial write of a fresh slot is not a live write.
func (l *Loader) slotIsLive(c migrationCtrl, slot uint32) (bool, error) {
	resolvable := slot == c.activeSlot
	if !resolvable {
		return false, nil
	}
	var nh bpfNextHop
	if err := l.objs.NextHops.Lookup(&slot, &nh); err != nil {
		return false, fmt.Errorf("reading next-hop slot %d: %w", slot, err)
	}
	return nh.Valid != 0, nil
}

// writeNextHop writes an endpoint pair into slot, marking it valid. The
// addresses must already be validated (validateSoftwireAddrs).
//
// It refuses to write a slot the datapath is currently resolving. That's the
// whole point of the slot indirection: a next_hop is copied into place on
// update with no RCU replacement, so overwriting a live slot lets a packet in
// flight read a half-updated endpoint and be encapsulated to a garbage peer.
// Enforcing it here rather than trusting each call site keeps the invariant
// true as more callers (graceful migration) are added.
func (l *Loader) writeNextHop(slot uint32, b4, aftr netip.Addr) error {
	c, err := l.readCtrl()
	if err != nil {
		return err
	}
	live, err := l.slotIsLive(c, slot)
	if err != nil {
		return err
	}
	if live {
		return fmt.Errorf("refusing to write next-hop slot %d: the datapath is resolving it "+
			"(state=%d active=%d old=%d); end the migration first", slot, c.state, c.activeSlot, c.oldSlot)
	}

	val := bpfNextHop{Valid: 1}
	val.B4Addr.In6U.U6Addr8 = b4.As16()
	val.AftrAddr.In6U.U6Addr8 = aftr.As16()
	if err := l.objs.NextHops.Put(&slot, &val); err != nil {
		return fmt.Errorf("setting next-hop slot %d: %w", slot, err)
	}
	return nil
}

// clearNextHop invalidates a slot, so encap can't resolve it and decap stops
// accepting that AFTR's traffic. Only ever applied to a slot the control word
// no longer points at (see CompleteMigration/AbortMigration).
func (l *Loader) clearNextHop(slot uint32) error {
	var val bpfNextHop // Valid == 0
	if err := l.objs.NextHops.Put(&slot, &val); err != nil {
		return fmt.Errorf("clearing next-hop slot %d: %w", slot, err)
	}
	return nil
}

// SetLANConfig installs the configuration for a LAN interface, keyed by its
// ifindex (as returned by AttachLAN).
func (l *Loader) SetLANConfig(ifindex uint32, cfg LANConfig) error {
	if !cfg.GatewayIP.Is4() {
		return fmt.Errorf("GatewayIP must be an IPv4 address, got %s", cfg.GatewayIP)
	}

	val := bpfLanConfig{
		GatewayIp: binary.BigEndian.Uint32(cfg.GatewayIP.AsSlice()),
		InnerMtu:  cfg.InnerMTU,
	}

	if err := l.objs.LanConfigs.Put(&ifindex, &val); err != nil {
		return fmt.Errorf("setting LAN config for ifindex %d: %w", ifindex, err)
	}

	return l.registerTxPort(ifindex)
}
