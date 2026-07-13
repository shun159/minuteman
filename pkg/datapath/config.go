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
	if err := l.writeActiveNextHop(0); err != nil {
		return err
	}

	return l.registerTxPort(cfg.WANIfindex)
}

// SwitchAFTR atomically moves the live softwire endpoint pair to (b4, aftr).
// It writes the currently-*inactive* slot in full, then flips active_nh to
// it: the slot the datapath is reading is never mutated, so it can never see
// a half-updated endpoint (the datapath copies a next_hop in place on update,
// with no RCU replacement — see the note on struct next_hop in
// bpf/datapath.bpf.c). This is the only supported way to change the AFTR on a
// running datapath; it encodes the write-inactive-then-flip sequence so a
// caller can't reintroduce the torn-read/blackhole hazard by driving the
// slots directly. The old endpoint is left valid in its slot, so decap keeps
// accepting its in-flight return traffic until a later switch recycles that
// slot. Both endpoints are validated before anything is written.
func (l *Loader) SwitchAFTR(b4, aftr netip.Addr) error {
	if err := validateSoftwireAddrs(b4, aftr); err != nil {
		return err
	}

	active, err := l.activeNextHop()
	if err != nil {
		return err
	}
	inactive := (active + 1) % numNextHops

	if err := l.writeNextHop(inactive, b4, aftr); err != nil {
		return err
	}
	return l.writeActiveNextHop(inactive)
}

// writeNextHop writes an endpoint pair into slot, marking it valid. The
// addresses must already be validated (validateSoftwireAddrs). Unexported:
// callers reach it only through SetB4Config (initial) and SwitchAFTR (live),
// which guarantee the slot written is never the one the datapath is using.
func (l *Loader) writeNextHop(slot uint32, b4, aftr netip.Addr) error {
	val := bpfNextHop{Valid: 1}
	val.B4Addr.In6U.U6Addr8 = b4.As16()
	val.AftrAddr.In6U.U6Addr8 = aftr.As16()
	if err := l.objs.NextHops.Put(&slot, &val); err != nil {
		return fmt.Errorf("setting next-hop slot %d: %w", slot, err)
	}
	return nil
}

// writeActiveNextHop flips active_nh to slot — a single-__u32 update, the
// atomic step that makes a switch take effect. Unexported for the same reason
// as writeNextHop.
func (l *Loader) writeActiveNextHop(slot uint32) error {
	key := uint32(0)
	if err := l.objs.ActiveNh.Put(&key, &slot); err != nil {
		return fmt.Errorf("setting active next-hop to slot %d: %w", slot, err)
	}
	return nil
}

// activeNextHop reads the currently-active next-hop slot index.
func (l *Loader) activeNextHop() (uint32, error) {
	key := uint32(0)
	var slot uint32
	if err := l.objs.ActiveNh.Lookup(&key, &slot); err != nil {
		return 0, fmt.Errorf("reading active next-hop: %w", err)
	}
	return slot, nil
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
