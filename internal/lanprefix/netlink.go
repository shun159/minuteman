package lanprefix

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// netlinkSocket is a single AF_NETLINK/NETLINK_ROUTE socket used to send
// RTM_NEWADDR/RTM_DELADDR requests and read back their acks. Not safe for
// concurrent use.
type netlinkSocket struct {
	fd  int
	seq uint32
}

// openNetlinkSocket opens and binds a NETLINK_ROUTE socket for sending
// address-configuration requests to the kernel.
func openNetlinkSocket() (*netlinkSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("lanprefix: opening netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("lanprefix: binding netlink socket: %w", err)
	}
	return &netlinkSocket{fd: fd}, nil
}

// Close closes the underlying socket.
func (s *netlinkSocket) Close() error {
	return unix.Close(s.fd)
}

// addAddr assigns addr/prefixLen to ifindex via RTM_NEWADDR. NLM_F_REPLACE
// makes this idempotent: re-asserting an address that's already assigned
// (e.g. on every lease reconciliation, even when nothing changed) succeeds
// without error, matching pkg/datapath's "safe to call repeatedly"
// convention for its own configuration setters.
func (s *netlinkSocket) addAddr(ifindex int, addr netip.Addr, prefixLen int) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE)
	return s.doRequest(unix.RTM_NEWADDR, flags, ifindex, addr, prefixLen)
}

// delAddr removes addr/prefixLen from ifindex via RTM_DELADDR. Used to
// clean up a stale address left over from a delegated prefix that changed
// across a lease renewal.
func (s *netlinkSocket) delAddr(ifindex int, addr netip.Addr, prefixLen int) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	return s.doRequest(unix.RTM_DELADDR, flags, ifindex, addr, prefixLen)
}

func (s *netlinkSocket) doRequest(rtmType uint16, flags uint16, ifindex int, addr netip.Addr, prefixLen int) error {
	s.seq++
	req := buildAddrMessage(rtmType, flags, s.seq, ifindex, addr, prefixLen)

	if err := unix.Send(s.fd, req, 0); err != nil {
		return fmt.Errorf("lanprefix: sending netlink request: %w", err)
	}

	buf := make([]byte, unix.Getpagesize())
	n, _, err := unix.Recvfrom(s.fd, buf, 0)
	if err != nil {
		return fmt.Errorf("lanprefix: reading netlink ack: %w", err)
	}
	return parseAckErrno(buf[:n], s.seq)
}
