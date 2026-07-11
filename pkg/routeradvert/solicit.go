package routeradvert

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// RFC 4861 §6.3.7's host-side solicitation cadence: how many Router
// Solicitations to transmit and how far apart.
const (
	maxRtrSolicitations     = 3
	rtrSolicitationInterval = 4 * time.Second
)

// rsFixedFieldsBytes is the length of a Router Solicitation's fixed fields
// after the ICMPv6 Type/Code/Checksum (RFC 4861 §4.1): Reserved (4).
const rsFixedFieldsBytes = 4

// marshalRouterSolicitation encodes a Router Solicitation (RFC 4861 §4.1)
// carrying a Source Link-Layer Address option for srcMAC (§4.1: SHOULD be
// included when the source address isn't the unspecified address, and a
// bound socket's kernel-picked link-local source never is). Checksum left
// zero -- kernel-computed, same as RouterAdvertisement.Marshal.
func marshalRouterSolicitation(srcMAC net.HardwareAddr) []byte {
	optBytes := Options{NewSourceLinkLayerAddress(srcMAC)}.Marshal()
	b := make([]byte, icmpv6FixedHeaderBytes+rsFixedFieldsBytes+len(optBytes))
	b[0] = icmpTypeRouterSolicit
	// b[1] Code = 0, b[2:4] Checksum (kernel), b[4:8] Reserved: all zero.
	copy(b[icmpv6FixedHeaderBytes+rsFixedFieldsBytes:], optBytes)
	return b
}

// SolicitRouters sends Router Solicitations out ifaceName to the
// All-Routers multicast address at RFC 4861 §6.3.7's host cadence (up to
// maxRtrSolicitations, rtrSolicitationInterval apart -- ~8s total),
// returning early if ctx is cancelled. The kernel itself receives and
// processes whatever Router Advertisements come back; this function only
// transmits, so there's nothing to read or return beyond send errors.
//
// It exists for the moment right after IPv6 forwarding gets enabled
// (pkg/datapath's configureWANSysctls): that 0->1 transition makes the
// kernel purge every RA-learned default route, and even with accept_ra=2
// the route only comes back at the upstream router's next unsolicited RA
// -- potentially minutes away, during which the WAN (and the datapath's
// own bpf_fib_lookup) has no route to the AFTR. Soliciting brings it back
// immediately.
func SolicitRouters(ctx context.Context, ifaceName string) error {
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("routeradvert: looking up interface %s: %w", ifaceName, err)
	}

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
	if err != nil {
		return fmt.Errorf("routeradvert: opening raw ICMPv6 socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.BindToDevice(fd, ifaceName); err != nil {
		return fmt.Errorf("routeradvert: binding to %s: %w", ifaceName, err)
	}
	// RFC 4861 §6.1.2: every NDP packet must have hop limit 255.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255); err != nil {
		return fmt.Errorf("routeradvert: setting multicast hop limit on %s: %w", ifaceName, err)
	}

	rs := marshalRouterSolicitation(ifi.HardwareAddr)
	dst := &unix.SockaddrInet6{Addr: allRoutersMulticast.As16(), ZoneId: uint32(ifi.Index)}
	for i := range maxRtrSolicitations {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(rtrSolicitationInterval):
			}
		}
		if err := unix.Sendto(fd, rs, 0, dst); err != nil {
			return fmt.Errorf("routeradvert: sending Router Solicitation on %s: %w", ifaceName, err)
		}
	}
	return nil
}
