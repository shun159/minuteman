package ndppd

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/shun159/miniteman/pkg/ndproxy"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/net/socket"
	"github.com/shun159/molecule/proc"
)

// lan is one LAN interface, with its socket.
type lan struct {
	name  string
	index int
	mac   net.HardwareAddr
	sock  socket.Socket
}

// sweep is the message of the sweep timer.
type sweep struct{}

// proxy is the ND proxy (see pkg/ndproxy): it answers the WAN's Neighbor
// Solicitations for hosts it has verified exist behind a LAN, probing there
// first, and has the routes process install the route of each host it
// confirms. Its state is pkg/ndproxy's State, a new one for each event
// that changes it; it sweeps it every SweepInterval, retransmitting probes
// and letting hosts gone quiet expire. now is the clock the State is kept
// by: the process's, given by molecule (molecule.Clocked).
//
// Its effects -- datagrams to send, sockets to re-arm -- are made by send
// and arm, which tests replace.
type proxy struct {
	genserver.Default[*ndproxy.State]
	wanRX, wanTX socket.Socket
	wanIndex     int
	wanMAC       net.HardwareAddr
	lans         []lan

	now  func() time.Time
	logf func(format string, args ...any)
	send func(s socket.Socket, to *syscall.SockaddrInet6, b []byte) molecule.Effect
	arm  func(s socket.Socket) molecule.Effect
}

var _ molecule.Clocked = proxy{}

func (p proxy) WithClock(now func() time.Time) any { p.now = now; return p }

func (p proxy) Init(proc.PID) (*ndproxy.State, []molecule.Effect, error) {
	return ndproxy.NewState(), molecule.Do(p.nextSweep()), nil
}

func (p proxy) HandleInfo(st *ndproxy.State, msg any) (*ndproxy.State, []molecule.Effect) {
	switch m := msg.(type) {
	case socket.DataMsg:
		if m.Sock.PID == p.wanRX.PID {
			st, effs := p.solicited(st, m.Bytes)
			return st, append(effs, p.arm(p.wanRX))
		}
		for _, l := range p.lans {
			if m.Sock.PID == l.sock.PID {
				st, effs := p.advertised(st, l, m.Bytes)
				return st, append(effs, p.arm(l.sock))
			}
		}
	case sweep:
		return p.swept(st)
	case socket.SendErrorMsg:
		// The next retransmitted Solicitation, or the next sweep's probe,
		// gets another chance.
		p.logf("ndppd: sending to %v: %v", m.To, m.Err)
	case socket.ErrorMsg:
		return st, molecule.Do(molecule.Stop{Reason: fmt.Errorf("ndppd: reading: %w", m.Err)})
	case socket.ClosedMsg:
		return st, molecule.Do(molecule.Stop{Reason: fmt.Errorf("ndppd: a socket closed")})
	}
	return st, nil
}

// solicited handles a packet from the WAN: a Neighbor Solicitation is
// answered at once for a host confirmed recently, or has the LANs probed.
func (p proxy) solicited(st *ndproxy.State, packet []byte) (*ndproxy.State, []molecule.Effect) {
	target, source, ok := ndproxy.ParseSolicitationPacket(packet)
	if !ok {
		return st, nil
	}
	next := st.Clone()
	reply, probe := next.OnWANSolicit(p.now(), target, source)
	var effs []molecule.Effect
	if reply != nil {
		effs = append(effs, p.advertise(reply))
	}
	if probe {
		effs = append(effs, p.probe(target)...)
	}
	return next, effs
}

// advertised handles a message from a LAN: a Neighbor Advertisement
// answering a probe confirms its host -- the WAN answered, its route
// installed.
func (p proxy) advertised(st *ndproxy.State, l lan, msg []byte) (*ndproxy.State, []molecule.Effect) {
	target, ok := ndproxy.ParseAdvertisement(msg)
	if !ok {
		return st, nil
	}
	next := st.Clone()
	reply, ok := next.OnLANAdvert(p.now(), l.name, target)
	if !ok {
		return st, nil // not answering a probe of ours
	}
	return next, molecule.Do(
		p.advertise(reply),
		molecule.Cast{To: RoutesName, Req: install{Target: reply.Target, Iface: reply.Iface}},
	)
}

// swept retransmits the probes due, and has the routes of hosts gone quiet
// removed.
func (p proxy) swept(st *ndproxy.State) (*ndproxy.State, []molecule.Effect) {
	next := st.Clone()
	retransmit, _, expired := next.Sweep(p.now())
	var effs []molecule.Effect
	for _, target := range retransmit {
		effs = append(effs, p.probe(target)...)
	}
	for _, e := range expired {
		effs = append(effs, molecule.Cast{To: RoutesName, Req: remove{Target: e.Target, Iface: e.Iface}})
	}
	return next, append(effs, p.nextSweep())
}

// advertise is the proxy's Neighbor Advertisement of reply on the WAN.
func (p proxy) advertise(reply *ndproxy.Reply) molecule.Effect {
	msg, dst := ndproxy.Advertisement(reply.Target, reply.Solicitor, p.wanMAC)
	return p.send(p.wanTX, sockaddr(dst, p.wanIndex), msg)
}

// probe is a Neighbor Solicitation for target out every LAN.
func (p proxy) probe(target netip.Addr) []molecule.Effect {
	effs := make([]molecule.Effect, 0, len(p.lans))
	for _, l := range p.lans {
		msg, dst := ndproxy.Solicitation(target, l.mac)
		effs = append(effs, p.send(l.sock, sockaddr(dst, l.index), msg))
	}
	return effs
}

func (p proxy) nextSweep() molecule.Effect {
	return molecule.StartTimer{Key: sweep{}, After: ndproxy.SweepInterval, Msg: sweep{}}
}

func sockaddr(addr netip.Addr, ifindex int) *syscall.SockaddrInet6 {
	return &syscall.SockaddrInet6{Addr: addr.As16(), ZoneId: uint32(ifindex)}
}
