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

// NumNextHops is the number of next-hop (softwire endpoint) slots the
// datapath holds, matching NUM_NEXT_HOPS in bpf/datapath.bpf.c. Two is
// enough for one live AFTR switch at a time: the outgoing AFTR in one slot,
// the incoming one in the other.
const NumNextHops = 2

// SetB4Config installs the DS-Lite softwire configuration used by both the
// encap and decap programs: the WAN-global fields (MACs, ifindex) plus the
// initial AFTR pair, which it places in next-hop slot 0 and makes active. It
// is a convenience for the common single-AFTR startup path; live AFTR
// re-discovery drives SetNextHop/SetActiveNextHop directly instead.
func (l *Loader) SetB4Config(cfg B4Config) error {
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

	if err := l.SetNextHop(0, cfg.B4Addr, cfg.AFTRAddr); err != nil {
		return err
	}
	if err := l.SetActiveNextHop(0); err != nil {
		return err
	}

	return l.registerTxPort(cfg.WANIfindex)
}

// SetNextHop installs a softwire endpoint pair (this B4's address + its
// AFTR's) into next-hop slot, marking it valid. Both must be IPv6. To switch
// the live AFTR safely, write the *inactive* slot with SetNextHop, then point
// traffic at it with SetActiveNextHop: the datapath copies a next_hop in
// place on update (no RCU), so overwriting the slot in use could be read
// half-updated.
func (l *Loader) SetNextHop(slot uint32, b4, aftr netip.Addr) error {
	if slot >= NumNextHops {
		return fmt.Errorf("next-hop slot %d out of range [0,%d)", slot, NumNextHops)
	}
	if !b4.Is6() || b4.Is4In6() {
		return fmt.Errorf("B4 address must be IPv6, got %s", b4)
	}
	if !aftr.Is6() || aftr.Is4In6() {
		return fmt.Errorf("AFTR address must be IPv6, got %s", aftr)
	}

	val := bpfNextHop{Valid: 1}
	val.B4Addr.In6U.U6Addr8 = b4.As16()
	val.AftrAddr.In6U.U6Addr8 = aftr.As16()
	if err := l.objs.NextHops.Put(&slot, &val); err != nil {
		return fmt.Errorf("setting next-hop slot %d: %w", slot, err)
	}
	return nil
}

// ClearNextHop marks a next-hop slot invalid, so the datapath stops
// encapsulating to it (if it were active) and stops accepting decap traffic
// from it. Used to retire the old AFTR once a switch has fully drained.
func (l *Loader) ClearNextHop(slot uint32) error {
	if slot >= NumNextHops {
		return fmt.Errorf("next-hop slot %d out of range [0,%d)", slot, NumNextHops)
	}
	var val bpfNextHop // Valid == 0
	if err := l.objs.NextHops.Put(&slot, &val); err != nil {
		return fmt.Errorf("clearing next-hop slot %d: %w", slot, err)
	}
	return nil
}

// SetActiveNextHop points the encap path (and the native-IPv6 fastpath's own
// B4 source address) at next-hop slot. The slot should already hold a valid
// endpoint pair (SetNextHop). This is the single-word flip that makes an AFTR
// switch take effect atomically.
func (l *Loader) SetActiveNextHop(slot uint32) error {
	if slot >= NumNextHops {
		return fmt.Errorf("next-hop slot %d out of range [0,%d)", slot, NumNextHops)
	}
	key := uint32(0)
	if err := l.objs.ActiveNh.Put(&key, &slot); err != nil {
		return fmt.Errorf("setting active next-hop to slot %d: %w", slot, err)
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
