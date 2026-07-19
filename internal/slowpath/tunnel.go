// Package slowpath manages the kernel ip6tnl companion device that gives
// minuteman's DS-Lite datapath softwire fragmentation and reassembly (RFC 6333
// §5.3) without doing either in XDP.
//
// The XDP fast path handles every whole, in-MTU softwire packet itself. The
// two cases it can't -- an oversized but fragmentable (non-DF) inner IPv4
// packet on the way out, and a fragmented softwire IPv6 packet on the way in --
// it hands to the kernel with XDP_PASS (see bpf/datapath.bpf.c's
// STAT_ENCAP_FRAG_SLOW / STAT_DECAP_FRAG_SLOW / STAT_DECAP_REASM_PASS). This
// package is what makes that hand-off land somewhere useful: an ip6tnl device
// (local = B4 address, remote = AFTR, mode ipip6, encaplimit none) plus an IPv4
// default route pointing at it, so
//
//   - outbound, the kernel's IPv4 forwarding path fragments the packet to the
//     tunnel MTU (WAN MTU - 40) and the ip6tnl encapsulates each piece, and
//   - inbound, the kernel reassembles the IPv6 fragments and the ip6tnl
//     decapsulates the result before it's forwarded to the LAN.
//
// It mirrors internal/wanextend.HostRoutes: one long-lived netlink socket,
// opened at construction, single-writer (the caller drives it from one
// goroutine), torn down on Close.
package slowpath

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"

	"github.com/shun159/miniteman/pkg/netlink"
)

// deviceName is the companion ip6tnl's fixed name. A stable name lets a
// restart find and replace a device an earlier crashed run left behind.
const deviceName = "mm-dslite0"

// tunnelOverhead is the outer IPv6 header the softwire adds (matching
// bpf/datapath_helpers.h's TUNNEL_L3_OVERHEAD): the tunnel MTU is the WAN MTU
// less this, so inner IPv4 is fragmented small enough that each encapsulated
// piece still fits the WAN.
const tunnelOverhead = 40

// minTunnelMTU floors the tunnel MTU at the IPv6 minimum (1280), so a
// pathologically small WAN MTU can't yield a nonsensical or negative one.
const minTunnelMTU = 1280

// defaultRoute is the IPv4 destination the companion device carries: all of
// them. The softwire is the B4's only IPv4 path.
var defaultRoute = netip.PrefixFrom(netip.IPv4Unspecified(), 0)

// Tunnel owns the companion ip6tnl device and the IPv4 default route pointing
// at it. Not safe for concurrent use: the caller (cmd/minuteman's single
// rediscovery owner, plus one-time startup) drives it from one goroutine.
type Tunnel struct {
	sock    *netlink.Socket
	mtu     int // tunnel device MTU (WAN MTU - tunnelOverhead)
	ifindex int
}

// New opens the netlink socket the Tunnel uses for its lifetime and records the
// tunnel MTU derived from wanMTU. It does not create the device yet -- call
// Ensure once the softwire endpoints are known.
func New(wanMTU int) (*Tunnel, error) {
	sock, err := netlink.Open()
	if err != nil {
		return nil, err
	}
	mtu := max(wanMTU-tunnelOverhead, minTunnelMTU)
	return &Tunnel{sock: sock, mtu: mtu}, nil
}

// Ensure creates the companion ip6tnl for the (b4, aftr) softwire and installs
// the IPv4 default route through it, replacing any device an earlier run left
// behind. It fails fast: a real home CPE has no other IPv4 path, and a missing
// ip6_tunnel kernel module (EOPNOTSUPP) is a misconfiguration the operator must
// see rather than a condition to silently degrade past.
func (t *Tunnel) Ensure(b4, aftr netip.Addr) error {
	// Remove a stale device from a previous (crashed) run before the exclusive
	// create below would collide with it. Absent is the normal case.
	if ifi, err := net.InterfaceByName(deviceName); err == nil {
		if err := t.sock.DelLink(ifi.Index); err != nil {
			return fmt.Errorf("slowpath: removing stale %s: %w", deviceName, err)
		}
	}

	if err := t.sock.AddIP6Tnl(deviceName, b4, aftr, t.mtu); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			return fmt.Errorf("slowpath: creating %s (is the ip6_tunnel kernel module available?): %w", deviceName, err)
		}
		return fmt.Errorf("slowpath: creating %s: %w", deviceName, err)
	}

	ifi, err := net.InterfaceByName(deviceName)
	if err != nil {
		return fmt.Errorf("slowpath: resolving %s after create: %w", deviceName, err)
	}
	t.ifindex = ifi.Index

	if err := t.sock.SetLinkUp(t.ifindex); err != nil {
		return fmt.Errorf("slowpath: bringing %s up: %w", deviceName, err)
	}
	if err := t.sock.AddRoute(t.ifindex, defaultRoute); err != nil {
		return fmt.Errorf("slowpath: adding IPv4 default route via %s: %w", deviceName, err)
	}
	return nil
}

// SetEndpoints repoints the companion device at new softwire endpoints in place
// (a WAN renumbering or AFTR migration), keeping the device and its IPv4
// default route. Called from the datapath's endpoint-mutation points after the
// fast path itself has switched, so it's a best-effort follow-up: unlike the
// startup Ensure, a transient failure here is logged, not fatal -- the fast
// path is already carrying whole packets on the new softwire, and only the
// fragmentation slow path lags until the next successful update.
func (t *Tunnel) SetEndpoints(b4, aftr netip.Addr) error {
	if t.ifindex == 0 {
		return fmt.Errorf("slowpath: SetEndpoints before Ensure")
	}
	if err := t.sock.SetIP6TnlEndpoints(t.ifindex, b4, aftr); err != nil {
		return fmt.Errorf("slowpath: repointing %s at %s->%s: %w", deviceName, b4, aftr, err)
	}
	return nil
}

// Close deletes the companion device (which takes its IPv4 default route with
// it) and closes the netlink socket. The delete is best-effort: a device that
// outlives the process is cleaned up by the next run's Ensure anyway, so a
// failure here is logged, not returned (matching wanextend.HostRoutes.Remove).
func (t *Tunnel) Close() error {
	if t.ifindex != 0 {
		if err := t.sock.DelLink(t.ifindex); err != nil {
			log.Printf("slowpath: removing %s on shutdown: %v", deviceName, err)
		}
	}
	return t.sock.Close()
}
