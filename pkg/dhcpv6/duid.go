package dhcpv6

import (
	"fmt"
	"net"
)

// HardwareTypeEthernet is the ARP hardware type for Ethernet (RFC 826),
// used in a DUID-LL's hardware-type field.
const HardwareTypeEthernet uint16 = 1

const duidTypeLL = 3 // RFC 3315 §9.4

// DUID is a DHCP Unique Identifier (RFC 3315 §9), opaque wire-format bytes.
type DUID []byte

// NewDUIDLL builds a DUID-LL (RFC 3315 §9.4): a link-layer address DUID.
// Its value is a pure function of hardwareType and mac, so regenerating it
// on every run yields the same stable identifier without persisting
// anything to disk -- unlike DUID-LLT (RFC 3315 §9.3), which embeds a
// timestamp and would look like a new identity on every regeneration.
func NewDUIDLL(hardwareType uint16, mac net.HardwareAddr) DUID {
	d := make(DUID, 4+len(mac))
	d[0] = byte(duidTypeLL >> 8)
	d[1] = byte(duidTypeLL)
	d[2] = byte(hardwareType >> 8)
	d[3] = byte(hardwareType)
	copy(d[4:], mac)
	return d
}

// DUIDLLFromInterface builds a DUID-LL from iface's Ethernet MAC address.
func DUIDLLFromInterface(iface *net.Interface) (DUID, error) {
	if len(iface.HardwareAddr) == 0 {
		return nil, fmt.Errorf("interface %s has no hardware address", iface.Name)
	}
	return NewDUIDLL(HardwareTypeEthernet, iface.HardwareAddr), nil
}
