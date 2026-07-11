// Package netlink is a minimal, hand-rolled AF_NETLINK/NETLINK_ROUTE
// client covering exactly what this project's CPE policy layers
// (internal/lanprefix, internal/wanextend) need: assigning/removing IPv6
// addresses, listing an interface's current addresses, and installing/
// removing routes. No netlink library dependency, matching this project's
// no-sidecar, no-external-process ethos (pkg/datapath/sysctl.go avoids
// `sysctl` exec the same way, internal/lanprefix originally avoided a
// netlink library the same way before this package was split out of it).
package netlink

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// Socket is a single AF_NETLINK/NETLINK_ROUTE socket used to send
// RTM_NEWADDR/RTM_DELADDR/RTM_GETADDR/RTM_NEWROUTE/RTM_DELROUTE requests
// and read back their acks or dump responses. Not safe for concurrent use.
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

// AddRoute installs a route to dst (typically a /128 host route) out
// ifindex, directly attached (no gateway), via RTM_NEWROUTE. NLM_F_REPLACE
// makes this idempotent, matching AddAddr.
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
