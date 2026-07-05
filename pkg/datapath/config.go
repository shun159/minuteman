package datapath

import (
	"encoding/binary"
	"fmt"
)

// registerTxPort makes ifindex a valid bpf_redirect_map() target by adding
// a self-mapped entry (ifindex -> ifindex) to the tx_ports DEVMAP_HASH.
func (l *Loader) registerTxPort(ifindex uint32) error {
	if err := l.objs.TxPorts.Put(&ifindex, &ifindex); err != nil {
		return fmt.Errorf("registering tx port for ifindex %d: %w", ifindex, err)
	}
	return nil
}

// SetB4Config installs the DS-Lite softwire configuration used by both the
// encap and decap programs.
func (l *Loader) SetB4Config(cfg B4Config) error {
	if !cfg.B4Addr.Is6() || cfg.B4Addr.Is4In6() {
		return fmt.Errorf("B4Addr must be an IPv6 address, got %s", cfg.B4Addr)
	}
	if !cfg.AFTRAddr.Is6() || cfg.AFTRAddr.Is4In6() {
		return fmt.Errorf("AFTRAddr must be an IPv6 address, got %s", cfg.AFTRAddr)
	}

	var val bpfB4Config
	val.B4Addr.In6U.U6Addr8 = cfg.B4Addr.As16()
	val.AftrAddr.In6U.U6Addr8 = cfg.AFTRAddr.As16()
	copy(val.SrcMac[:], cfg.SrcMAC)
	copy(val.DstMac[:], cfg.DstMAC)
	val.WanIfindex = cfg.WANIfindex

	key := uint32(0)
	if err := l.objs.B4ConfigMap.Put(&key, &val); err != nil {
		return fmt.Errorf("setting B4 config: %w", err)
	}

	return l.registerTxPort(cfg.WANIfindex)
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
