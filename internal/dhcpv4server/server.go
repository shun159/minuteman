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
	"github.com/shun159/molecule/kvs"
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
//
// leases holds the table of each interface whose leases are kept across
// restarts, opened with OpenLeases; an interface without one keeps them in
// memory only. The tables outlive the tree: their owner closes them once
// it has stopped.
func Spec(cfgs []dhcpv4.InterfaceConfig, leases map[string]*Leases) (supervisor.Spec, error) {
	if len(cfgs) == 0 {
		return supervisor.Spec{}, errors.New("dhcpv4: no interfaces configured")
	}
	var children []supervisor.ChildSpec
	for _, cfg := range cfgs {
		children = append(children, supervisor.ChildSpec{
			ID:    "dhcpv4 " + cfg.Iface,
			Start: supervisor.StartFunc(starter(cfg, leases[cfg.Iface])),
		})
	}
	return supervisor.Spec{Name: molecule.Local("dhcpv4"), Strategy: supervisor.OneForOne, Children: children}, nil
}

// Leases is the table of an interface's committed leases, by client ID.
type Leases = kvs.Table[string, dhcpv4.Lease]

// OpenLeases opens the lease table kept in dir, made if missing. A lease is
// on disk before the ACK granting it goes out (kvs.SyncEach).
func OpenLeases(dir string) (*Leases, error) {
	return kvs.Open(dir, kvs.Options[string, dhcpv4.Lease]{})
}

// restore puts the leases kept in leases back into pool, and deletes those
// it no longer takes: expired, or no longer in the pool.
func restore(pool *dhcpv4.Pool, leases *Leases, now time.Time) error {
	var gone []string
	for id, l := range leases.All() {
		if !pool.Restore(id, l, now) {
			gone = append(gone, id)
		}
	}
	for _, id := range gone {
		if err := leases.Delete(id); err != nil {
			return err
		}
	}
	return nil
}

// ipProto is ETH_P_IP in network byte order, as AF_PACKET takes it.
var ipProto = bits.ReverseBytes16(unix.ETH_P_IP)

// starter starts the server of cfg's interface: its pool, with the leases
// kept in leases if any, then its packet socket -- owned by parent,
// passive, until the server owns it.
func starter(cfg dhcpv4.InterfaceConfig, leases *Leases) supervisor.StartFunc {
	return func(ctx context.Context, parent *proc.Self) (proc.PID, error) {
		pool, err := dhcpv4.NewPool(cfg.Subnet, cfg.ServerIP, cfg.LeaseTime)
		if err != nil {
			return proc.PID{}, err
		}
		if leases != nil {
			if err := restore(pool, leases, time.Now()); err != nil {
				return proc.PID{}, fmt.Errorf("dhcpv4: restoring the leases of %s: %w", cfg.Iface, err)
			}
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
		s := server{cfg: cfg, sock: sock, ifindex: ifi.Index, pool: pool, leases: leases, logf: log.Printf}
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
// changes it. now is the clock leases are kept by: the process's, given by
// molecule (molecule.Clocked).
//
// With leases, a request changing a client's committed lease writes it to
// the table, and a reply granting it waits until it is on disk: an ACK is
// never lost to a restart that would forget it.
type server struct {
	genserver.Default[*dhcpv4.Pool]
	cfg     dhcpv4.InterfaceConfig
	sock    socket.Socket
	ifindex int
	pool    *dhcpv4.Pool // the pool to start with
	leases  *Leases      // nil: leases kept in memory only
	now     func() time.Time
	logf    func(format string, args ...any)
}

// held is a reply held until the lease it grants is on disk.
type held struct {
	to    syscall.Sockaddr
	frame []byte
}

var _ molecule.Clocked = server{}

func (s server) WithClock(now func() time.Time) any { s.now = now; return s }

func (s server) Init(proc.PID) (*dhcpv4.Pool, []molecule.Effect, error) {
	return s.pool, nil, nil
}

func (s server) HandleInfo(pool *dhcpv4.Pool, msg any) (*dhcpv4.Pool, []molecule.Effect) {
	switch m := msg.(type) {
	case socket.DataMsg:
		next, to, frame, id := s.answer(pool, m.Bytes)
		if put, del := s.keep(pool, next, id); put != nil && frame != nil {
			// The next request is taken at once; the reply waits.
			return next, molecule.Do(s.sock.SetActiveEffect(socket.Once), s.leases.PutEffect(id, *put, &held{to, frame}))
		} else if put != nil {
			return next, s.reply(to, frame, s.leases.PutEffect(id, *put, nil))
		} else if del {
			return next, s.reply(to, frame, s.leases.DeleteEffect(id, nil))
		}
		return next, s.reply(to, frame)
	case kvs.Durable:
		// A lease the table failed to keep is granted all the same: a client
		// answered matters more than a lease remembered across a restart.
		if m.Err != nil {
			s.logf("dhcpv4: keeping a lease on %s: %v", s.cfg.Iface, m.Err)
		}
		h := m.Tag.(*held)
		return pool, molecule.Do(s.sock.SendEffect(h.to, h.frame))
	case socket.SendErrorMsg:
		s.logf("dhcpv4: sending a reply on %s: %v", s.cfg.Iface, m.Err)
	case socket.ErrorMsg:
		return pool, molecule.Do(molecule.Stop{Reason: fmt.Errorf("dhcpv4: reading on %s: %w", s.cfg.Iface, m.Err)})
	case socket.ClosedMsg:
		return pool, molecule.Do(molecule.Stop{Reason: fmt.Errorf("dhcpv4: socket on %s closed", s.cfg.Iface)})
	}
	return pool, nil
}

// reply is effs, then the effect sending frame to to if any, which also
// asks for the next request -- or only asks for it.
func (s server) reply(to syscall.Sockaddr, frame []byte, effs ...molecule.Effect) []molecule.Effect {
	if frame == nil {
		return append(effs, s.sock.SetActiveEffect(socket.Once))
	}
	return append(effs, s.sock.SendActiveEffect(to, frame, socket.Once))
}

// keep tells what to write to the lease table of the change a request
// made to client id's committed lease, from pool to next: the lease to
// put, or that it is to be deleted, or nothing.
func (s server) keep(pool, next *dhcpv4.Pool, id string) (put *dhcpv4.Lease, del bool) {
	if s.leases == nil || id == "" {
		return nil, false
	}
	now := s.now()
	was, had := pool.Committed(id, now)
	is, has := next.Committed(id, now)
	switch {
	case has && (!had || is != was):
		return &is, false
	case had && !has:
		return nil, true
	}
	return nil, false
}

// answer handles packet, as the socket delivers it: the pool after it, the
// reply framed and the address to send it to, if any, and the ID of the
// client asking. The pool given is left as it was.
func (s server) answer(pool *dhcpv4.Pool, packet []byte) (*dhcpv4.Pool, syscall.Sockaddr, []byte, string) {
	req, ok := dhcpv4.ParseRequest(packet)
	if !ok {
		return pool, nil, nil, ""
	}
	id := req.Options.ClientID(req.CHAddr)
	next := pool.Clone()
	reply := dhcpv4.Handle(s.cfg, next, req, s.now())
	if reply == nil {
		return next, nil, nil, id
	}
	frame, mac := dhcpv4.Frame(s.cfg.ServerIP, reply)
	to := &syscall.SockaddrLinklayer{Protocol: ipProto, Ifindex: s.ifindex, Halen: uint8(len(mac))}
	copy(to.Addr[:], mac)
	return next, to, frame, id
}
