// Package pollfd hands a raw socket to the Go runtime's poller, so that
// closing it wakes a read blocked on it.
//
// pkg/dhcpv4, pkg/ndproxy and pkg/routeradvert read AF_PACKET and raw ICMPv6
// sockets, which the net package has no type for, with unix.Recvfrom. On a
// blocking fd that is a recvfrom(2) the goroutine sits in, and close(2) from
// another goroutine does not wake it on Linux: the read returns only when a
// packet arrives or the interface goes away, so a server waiting for its
// reader on shutdown waits for that. Through the poller, the read parks in
// the runtime instead, and Close wakes it with os.ErrClosed.
package pollfd

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// FD is a socket read and written through the poller.
type FD struct {
	f  *os.File
	rc syscall.RawConn
}

// New takes over fd, a socket opened with SOCK_NONBLOCK and set up with
// whatever socket options it needs. On failure it closes fd.
func New(fd int, name string) (*FD, error) {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		unix.Close(fd)
		return nil, os.ErrInvalid
	}
	rc, err := f.SyscallConn()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &FD{f: f, rc: rc}, nil
}

// Recvfrom receives a packet into buf, waiting for one. After Close, it
// returns an error.
func (p *FD) Recvfrom(buf []byte) (n int, from unix.Sockaddr, err error) {
	rerr := p.rc.Read(func(fd uintptr) bool {
		n, from, err = unix.Recvfrom(int(fd), buf, 0)
		return err != unix.EAGAIN
	})
	if rerr != nil {
		return 0, nil, rerr
	}
	return n, from, err
}

// Sendto sends b to to, waiting for room in the socket's buffer.
func (p *FD) Sendto(b []byte, to unix.Sockaddr) error {
	var err error
	werr := p.rc.Write(func(fd uintptr) bool {
		err = unix.Sendto(int(fd), b, 0, to)
		return err != unix.EAGAIN
	})
	if werr != nil {
		return werr
	}
	return err
}

// Close closes the socket, waking a Recvfrom or Sendto waiting on it.
func (p *FD) Close() error { return p.f.Close() }
