package wanextend

import (
	"fmt"
	"log"
	"net"
	"net/netip"

	"github.com/shun159/miniteman/pkg/netlink"
)

// HostRoutes installs and removes per-LAN-host /128 routes via
// pkg/netlink, matching pkg/ndproxy.Config's OnActive/OnInactive callback
// shapes. A route is needed at all only because NDProxy's model shares one
// /64 across the WAN and every LAN interface: without one, the kernel has
// no way to know which LAN interface a confirmed-active target lives
// behind, and would fall back to whatever its normal routing decision
// picks -- wrong whenever there's more than one LAN interface, and
// unpredictable even with one.
type HostRoutes struct {
	sock *netlink.Socket
}

// NewHostRoutes opens the netlink socket HostRoutes uses for the lifetime
// of the caller's pkg/ndproxy.Serve run. Not safe for concurrent use, but
// Serve only ever calls OnActive/OnInactive from its own single select
// loop, so a shared *netlink.Socket needs no locking here.
func NewHostRoutes() (*HostRoutes, error) {
	sock, err := netlink.Open()
	if err != nil {
		return nil, err
	}
	return &HostRoutes{sock: sock}, nil
}

// Close closes the underlying netlink socket.
func (h *HostRoutes) Close() error {
	return h.sock.Close()
}

// Install adds a /128 route to target out iface -- pkg/ndproxy.Config's
// OnActive.
func (h *HostRoutes) Install(target netip.Addr, iface string) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("wanextend: looking up interface %s: %w", iface, err)
	}
	if err := h.sock.AddRoute(ifi.Index, netip.PrefixFrom(target, target.BitLen())); err != nil {
		return fmt.Errorf("wanextend: installing route to %s via %s: %w", target, iface, err)
	}
	return nil
}

// Remove deletes the /128 route to target installed by Install --
// pkg/ndproxy.Config's OnInactive. Errors are logged, not returned:
// OnInactive has no error return (unlike OnActive), since a route that
// fails to be removed is stale but harmless -- nothing routes to it once
// Serve stops confirming target active, and a future reactivation's
// Install (NLM_F_REPLACE) overwrites it anyway.
func (h *HostRoutes) Remove(target netip.Addr, iface string) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		log.Printf("wanextend: looking up interface %s to remove route to %s: %v", iface, target, err)
		return
	}
	if err := h.sock.DelRoute(ifi.Index, netip.PrefixFrom(target, target.BitLen())); err != nil {
		log.Printf("wanextend: removing route to %s via %s: %v", target, iface, err)
	}
}
