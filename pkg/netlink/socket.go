// Package netlink is a minimal, hand-rolled AF_NETLINK/NETLINK_ROUTE
// client covering exactly what this project's CPE policy layers
// (internal/lanprefix, internal/wanextend, internal/slowpath) need:
// assigning/removing IPv6 addresses, listing an interface's current
// addresses, installing/removing routes, and creating/tearing down the
// DS-Lite companion ip6tnl device. No netlink library dependency, matching
// this project's
// no-sidecar, no-external-process ethos (pkg/datapath/sysctl.go avoids
// `sysctl` exec the same way, internal/lanprefix originally avoided a
// netlink library the same way before this package was split out of it).
package netlink

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// Socket is a single AF_NETLINK/NETLINK_ROUTE socket used to send
// RTM_NEWADDR/RTM_DELADDR/RTM_GETADDR/RTM_NEWROUTE/RTM_DELROUTE and
// RTM_NEWLINK/RTM_DELLINK requests and read back their acks or dump responses.
// Not safe for concurrent use.
type Socket struct {
	fd  int
	seq uint32
}

// Open opens and binds a NETLINK_ROUTE socket.
func Open() (*Socket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink: opening socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netlink: binding socket: %w", err)
	}
	return &Socket{fd: fd}, nil
}

// Close closes the underlying socket.
func (s *Socket) Close() error {
	return unix.Close(s.fd)
}

// AddAddr assigns addr/prefixLen to ifindex via RTM_NEWADDR. NLM_F_REPLACE
// makes this idempotent: re-asserting an address that's already assigned
// succeeds without error.
func (s *Socket) AddAddr(ifindex int, addr netip.Addr, prefixLen int) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE)
	s.seq++
	return s.sendAndAck(buildAddrMessage(unix.RTM_NEWADDR, flags, s.seq, ifindex, addr, prefixLen), s.seq)
}

// DelAddr removes addr/prefixLen from ifindex via RTM_DELADDR.
func (s *Socket) DelAddr(ifindex int, addr netip.Addr, prefixLen int) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	s.seq++
	return s.sendAndAck(buildAddrMessage(unix.RTM_DELADDR, flags, s.seq, ifindex, addr, prefixLen), s.seq)
}

// Addrs lists ifindex's currently-assigned global-scope (RT_SCOPE_UNIVERSE)
// IPv6 addresses via an RTM_GETADDR dump -- e.g. to discover a prefix the
// kernel assigned to the interface itself via SLAAC, which nothing in this
// project otherwise tracks in Go.
func (s *Socket) Addrs(ifindex int) ([]netip.Prefix, error) {
	s.seq++
	seq := s.seq
	if err := unix.Send(s.fd, buildGetAddrMessage(seq), 0); err != nil {
		return nil, fmt.Errorf("netlink: sending RTM_GETADDR: %w", err)
	}

	var result []netip.Prefix
	buf := make([]byte, unix.Getpagesize())
	for {
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("netlink: reading RTM_GETADDR dump: %w", err)
		}
		msgs, err := walkMessages(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			switch m.Type {
			case unix.NLMSG_DONE:
				return result, nil
			case unix.NLMSG_ERROR:
				if err := parseAckErrno(m.Raw, seq); err != nil {
					return nil, err
				}
			case unix.RTM_NEWADDR:
				if p, ok := parseIfAddrMsg(m.Raw[unix.SizeofNlMsghdr:], ifindex); ok {
					result = append(result, p)
				}
			}
		}
	}
}

// SourceForDest asks the kernel which local IPv6 address it would use as the
// source when sending to dst out ifindex -- an RTM_GETROUTE query (`ip route
// get <dst> oif <ifindex>`), so the kernel runs its own RFC 6724 source-address
// selection (deprecated-avoidance, scope match, longest-match) and returns the
// chosen source in RTA_PREFSRC. minuteman uses this to pick the B4's own
// softwire source toward the AFTR without reimplementing that selection.
//
// ok is false when the kernel reports the destination unreachable out ifindex
// (an ENETUNREACH/EHOSTUNREACH/ENETDOWN errno) or replies with a route carrying
// no RTA_PREFSRC: at startup, before the WAN's RA-learned default route is back,
// the interface has no usable global source yet, so the caller retries. Any
// *other* netlink errno (e.g. EINVAL from a malformed request) is returned as an
// error rather than absorbed into that retry, so a real bug surfaces instead of
// looping forever.
func (s *Socket) SourceForDest(ifindex int, dst netip.Addr) (src netip.Addr, ok bool, err error) {
	s.seq++
	seq := s.seq
	if err := unix.Send(s.fd, buildGetRouteMessage(seq, ifindex, dst), 0); err != nil {
		return netip.Addr{}, false, fmt.Errorf("netlink: sending RTM_GETROUTE: %w", err)
	}

	buf := make([]byte, unix.Getpagesize())
	n, _, err := unix.Recvfrom(s.fd, buf, 0)
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("netlink: reading RTM_GETROUTE reply: %w", err)
	}
	msgs, err := walkMessages(buf[:n])
	if err != nil {
		return netip.Addr{}, false, err
	}
	for _, m := range msgs {
		switch m.Type {
		case unix.NLMSG_ERROR:
			// A route-get for an unreachable dst comes back as an errno, not a
			// route with no prefsrc. Reachability-class errnos mean "no source
			// yet" (the WAN route isn't back) -> retry; any other errno is a real
			// error (e.g. a malformed request), returned rather than absorbed into
			// the caller's retry so it can't loop forever. parseAckErrno returns
			// nil for the errno==0 case, which an RTM_GETROUTE reply never is.
			if err := parseAckErrno(m.Raw, seq); err != nil {
				if isNoRouteErrno(err) {
					return netip.Addr{}, false, nil
				}
				return netip.Addr{}, false, fmt.Errorf("netlink: RTM_GETROUTE: %w", err)
			}
		case unix.RTM_NEWROUTE:
			if src, ok := parseRoutePrefsrc(m.Raw[unix.SizeofNlMsghdr:]); ok {
				return src, true, nil
			}
		}
	}
	return netip.Addr{}, false, nil
}

// isNoRouteErrno reports whether an RTM_GETROUTE NLMSG_ERROR errno means "no
// route/source to the destination yet" -- expected at startup while the WAN's
// RA-learned route is still absent, so SourceForDest reports it as ok=false for
// the caller to retry rather than as a hard error. Every other errno (a
// malformed request, an unexpected kernel error) is surfaced instead.
func isNoRouteErrno(err error) bool {
	return errors.Is(err, unix.ENETUNREACH) ||
		errors.Is(err, unix.EHOSTUNREACH) ||
		errors.Is(err, unix.ENETDOWN)
}

// AddRoute installs a route to dst out ifindex, directly attached (no
// gateway), via RTM_NEWROUTE. NLM_F_REPLACE makes this idempotent, matching
// AddAddr. dst may be IPv4 or IPv6 (the family follows the prefix): an IPv6
// /128 host route for internal/wanextend, or the IPv4 default route (0.0.0.0/0)
// internal/slowpath points at the companion ip6tnl.
func (s *Socket) AddRoute(ifindex int, dst netip.Prefix) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE)
	s.seq++
	return s.sendAndAck(buildRouteMessage(unix.RTM_NEWROUTE, flags, s.seq, ifindex, dst), s.seq)
}

// DelRoute removes a route to dst out ifindex via RTM_DELROUTE.
func (s *Socket) DelRoute(ifindex int, dst netip.Prefix) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	s.seq++
	return s.sendAndAck(buildRouteMessage(unix.RTM_DELROUTE, flags, s.seq, ifindex, dst), s.seq)
}

// AddIP6Tnl creates an ip6tnl device named name in ipip6 (IPv4-in-IPv6) mode
// with softwire endpoints local (the B4 address) and remote (the AFTR), MTU
// mtu, and `encaplimit none` -- the companion slow-path device the kernel uses
// to fragment/reassemble softwire traffic XDP hands up (RFC 6333 §5.3). Fails
// if a device by that name already exists (NLM_F_EXCL); callers delete a stale
// one first. An EOPNOTSUPP here means the ip6_tunnel kernel module is
// unavailable.
func (s *Socket) AddIP6Tnl(name string, local, remote netip.Addr, mtu int) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL)
	s.seq++
	return s.sendAndAck(buildAddIP6TnlMessage(s.seq, flags, name, local, remote, mtu), s.seq)
}

// SetIP6TnlEndpoints repoints an existing ip6tnl (identified by ifindex) at new
// softwire endpoints via a changelink, in place -- so a WAN renumbering or AFTR
// migration updates the device without tearing down the IPv4 default route that
// points at it.
func (s *Socket) SetIP6TnlEndpoints(ifindex int, local, remote netip.Addr) error {
	s.seq++
	return s.sendAndAck(buildChangeIP6TnlMessage(s.seq, ifindex, local, remote), s.seq)
}

// SetLinkUp brings ifindex administratively up (IFF_UP).
func (s *Socket) SetLinkUp(ifindex int) error {
	s.seq++
	return s.sendAndAck(buildSetLinkUpMessage(s.seq, ifindex), s.seq)
}

// DelLink deletes the network device ifindex (RTM_DELLINK).
func (s *Socket) DelLink(ifindex int) error {
	s.seq++
	return s.sendAndAck(buildDelLinkMessage(s.seq, ifindex), s.seq)
}

func (s *Socket) sendAndAck(req []byte, seq uint32) error {
	if err := unix.Send(s.fd, req, 0); err != nil {
		return fmt.Errorf("netlink: sending request: %w", err)
	}

	buf := make([]byte, unix.Getpagesize())
	n, _, err := unix.Recvfrom(s.fd, buf, 0)
	if err != nil {
		return fmt.Errorf("netlink: reading ack: %w", err)
	}
	return parseAckErrno(buf[:n], seq)
}
