// Package dhcpv4server runs pkg/dhcpv4's LAN-side DHCPv4 server as a
// molecule supervision tree: one process per LAN interface, owning that
// interface's packet socket and its lease pool.
package dhcpv4server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/bits"
	"net"
	"syscall"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv4"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/net/socket"
	"github.com/shun159/molecule/proc"
	"golang.org/x/sys/unix"
)

// Spec is the supervision tree of the server, one child per interface of
// cfgs:
//
//	dhcpv4 (one_for_one)
//	├── dhcpv4 <iface>   the server of one LAN interface: its socket, its pool
//	└── ...
//
// Each child's start validates the interface's pool and opens its socket,
// so an invalid subnet, a missing interface or a socket failure fails the
// tree's start -- and minuteman's -- rather than surfacing later.
func Spec(cfgs []dhcpv4.InterfaceConfig) (supervisor.Spec, error) {
	if len(cfgs) == 0 {
		return supervisor.Spec{}, errors.New("dhcpv4: no interfaces configured")
	}
	var children []supervisor.ChildSpec
	for _, cfg := range cfgs {
		children = append(children, supervisor.ChildSpec{
			ID:    "dhcpv4 " + cfg.Iface,
			Start: supervisor.StartFunc(starter(cfg)),
		})
	}
	return supervisor.Spec{Name: molecule.Local("dhcpv4"), Strategy: supervisor.OneForOne, Children: children}, nil
}

// ipProto is ETH_P_IP in network byte order, as AF_PACKET takes it.
var ipProto = bits.ReverseBytes16(unix.ETH_P_IP)

// starter starts the server of cfg's interface: its pool, then its packet
// socket -- owned by parent, passive, until the server owns it.
func starter(cfg dhcpv4.InterfaceConfig) supervisor.StartFunc {
	return func(ctx context.Context, parent *proc.Self) (proc.PID, error) {
		pool, err := dhcpv4.NewPool(cfg.Subnet, cfg.ServerIP, cfg.LeaseTime)
		if err != nil {
			return proc.PID{}, err
		}
		ifi, err := net.InterfaceByName(cfg.Iface)
		if err != nil {
			return proc.PID{}, fmt.Errorf("dhcpv4: looking up interface %s: %w", cfg.Iface, err)
		}
		sock, err := socket.Open(parent, unix.AF_PACKET, unix.SOCK_DGRAM, int(ipProto), func(fd int) error {
			// The filter goes on before the bind, so no unfiltered packet
			// is ever queued.
			prog := unix.SockFprog{Len: uint16(len(dhcpv4.Filter)), Filter: &dhcpv4.Filter[0]}
			if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
				return fmt.Errorf("dhcpv4: attaching DHCP filter on %s: %w", cfg.Iface, err)
			}
			if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: ipProto, Ifindex: ifi.Index}); err != nil {
				return fmt.Errorf("dhcpv4: binding packet socket to %s: %w", cfg.Iface, err)
			}
			return nil
		}, socket.Options{})
		if err != nil {
			return proc.PID{}, fmt.Errorf("dhcpv4: opening packet socket on %s: %w", cfg.Iface, err)
		}
		s := server{cfg: cfg, sock: sock, ifindex: ifi.Index, pool: pool, now: time.Now, logf: log.Printf}
		pid, err := genserver.Child(s).StartLink(ctx, parent)
		if err == nil {
			if err = sock.ControllingProcess(ctx, parent, pid); err == nil {
				err = sock.SetActive(ctx, parent, socket.Once)
			}
			if err != nil {
				parent.Exit(pid, proc.Kill)
			}
		}
		if err != nil {
			sock.Close(context.Background(), parent)
			return proc.PID{}, err
		}
		return pid, nil
	}
}

// server is the DHCPv4 server of one LAN interface: it takes requests one
// at a time from its socket, answers them with dhcpv4.Handle, and sends the
// replies framed by dhcpv4.Frame to the client's link-layer address. Its
// state is the interface's lease pool, a new one for each request that
// changes it. now is the clock leases are kept by, which a behaviour has no
// other way to read.
type server struct {
	genserver.Default[*dhcpv4.Pool]
	cfg     dhcpv4.InterfaceConfig
	sock    socket.Socket
	ifindex int
	pool    *dhcpv4.Pool // the pool to start with
	now     func() time.Time
	logf    func(format string, args ...any)
}

func (s server) Init(proc.PID) (*dhcpv4.Pool, []molecule.Effect, error) {
	return s.pool, nil, nil
}

func (s server) HandleInfo(pool *dhcpv4.Pool, msg any) (*dhcpv4.Pool, []molecule.Effect) {
	switch m := msg.(type) {
	case socket.DataMsg:
		pool, to, frame := s.answer(pool, m.Bytes)
		if frame == nil {
			return pool, molecule.Do(s.sock.SetActiveEffect(socket.Once))
		}
		return pool, molecule.Do(s.sock.SendActiveEffect(to, frame, socket.Once))
	case socket.SendErrorMsg:
		s.logf("dhcpv4: sending a reply on %s: %v", s.cfg.Iface, m.Err)
	case socket.ErrorMsg:
		return pool, molecule.Do(molecule.Stop{Reason: fmt.Errorf("dhcpv4: reading on %s: %w", s.cfg.Iface, m.Err)})
	case socket.ClosedMsg:
		return pool, molecule.Do(molecule.Stop{Reason: fmt.Errorf("dhcpv4: socket on %s closed", s.cfg.Iface)})
	}
	return pool, nil
}

// answer handles packet, as the socket delivers it: the pool after it, and
// the reply framed and the address to send it to, if any. The pool given is
// left as it was.
func (s server) answer(pool *dhcpv4.Pool, packet []byte) (*dhcpv4.Pool, syscall.Sockaddr, []byte) {
	req, ok := dhcpv4.ParseRequest(packet)
	if !ok {
		return pool, nil, nil
	}
	next := pool.Clone()
	reply := dhcpv4.Handle(s.cfg, next, req, s.now())
	if reply == nil {
		return next, nil, nil
	}
	frame, mac := dhcpv4.Frame(s.cfg.ServerIP, reply)
	to := &syscall.SockaddrLinklayer{Protocol: ipProto, Ifindex: s.ifindex, Halen: uint8(len(mac))}
	copy(to.Addr[:], mac)
	return next, to, frame
}
