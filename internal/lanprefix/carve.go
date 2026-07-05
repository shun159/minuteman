// Package lanprefix implements the CPE-policy decisions around a
// DHCPv6-PD delegated prefix: carving one /64 per LAN interface out of it,
// assigning an address from that /64 to the interface via netlink, and
// advertising it to LAN clients via Router Advertisements (RAManager) so
// they can SLAAC an address out of it themselves.
package lanprefix

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// lanSubnetBits is the fixed subnet size handed to each LAN interface: a
// /64, the smallest unit SLAAC (see RAManager, which advertises it via
// Router Advertisements) can work with.
const lanSubnetBits = 64

// SubnetFor carves the /64 for the index'th LAN interface (0-based, in
// -lan flag order) out of delegated, by writing index into the bits between
// delegated's prefix length and bit 64. E.g. a /56 delegation has 8 such
// bits, so indices 0-255 each get a distinct /64.
func SubnetFor(delegated netip.Prefix, index int) (netip.Prefix, error) {
	if !delegated.Addr().Is6() || delegated.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("lanprefix: delegated prefix must be IPv6, got %s", delegated)
	}
	if delegated.Bits() > lanSubnetBits {
		return netip.Prefix{}, fmt.Errorf("lanprefix: delegated prefix %s is already narrower than /%d, no room to carve a LAN subnet", delegated, lanSubnetBits)
	}
	if index < 0 {
		return netip.Prefix{}, fmt.Errorf("lanprefix: LAN index %d must not be negative", index)
	}

	subnetBits := lanSubnetBits - delegated.Bits()
	if subnetBits < 64 && index >= 1<<subnetBits {
		return netip.Prefix{}, fmt.Errorf("lanprefix: LAN index %d exceeds delegated %s's capacity of %d /%d subnets",
			index, delegated, 1<<subnetBits, lanSubnetBits)
	}

	raw := delegated.Addr().As16()
	network := binary.BigEndian.Uint64(raw[:8])
	network = (network &^ (uint64(1)<<subnetBits - 1)) | uint64(index)
	binary.BigEndian.PutUint64(raw[:8], network)
	for i := 8; i < 16; i++ {
		raw[i] = 0
	}

	return netip.PrefixFrom(netip.AddrFrom16(raw), lanSubnetBits), nil
}

// AssignedAddress returns the address this project assigns to the LAN
// interface itself within subnet: subnet's network address with the last
// byte set to 1 (the conventional CPE-gateway "::1" address).
func AssignedAddress(subnet netip.Prefix) (netip.Addr, error) {
	if !subnet.Addr().Is6() || subnet.Addr().Is4In6() {
		return netip.Addr{}, fmt.Errorf("lanprefix: subnet must be IPv6, got %s", subnet)
	}
	if subnet.Bits() != lanSubnetBits {
		return netip.Addr{}, fmt.Errorf("lanprefix: subnet must be a /%d, got %s", lanSubnetBits, subnet)
	}

	raw := subnet.Addr().As16()
	raw[15] = 1
	return netip.AddrFrom16(raw), nil
}
