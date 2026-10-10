package ndppd

import (
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/shun159/miniteman/pkg/ndproxy"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/net/socket"
	"github.com/shun159/molecule/proc"
)

// Effects the proxy under test returns in place of sending and arming.
type (
	sent struct {
		molecule.Extension
		sock proc.PID
		to   netip.Addr
		zone uint32
		msg  []byte
	}
	armed struct {
		molecule.Extension
		sock proc.PID
	}
)

var (
	wanMAC    = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	solicitor = netip.MustParseAddr("2001:db8::1")
	target    = netip.MustParseAddr("2001:db8::abcd")
)

type rig struct {
	p   proxy
	now time.Time
}

func newRig(t *testing.T) *rig {
	n := proc.NewNode("")
	r := &rig{now: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)}
	r.p = proxy{
		wanRX: socket.Socket{PID: n.NewPID()}, wanTX: socket.Socket{PID: n.NewPID()},
		wanIndex: 2, wanMAC: wanMAC,
		lans: []lan{
			{name: "lan0", index: 3, mac: net.HardwareAddr{2, 0, 0, 0, 0, 3}, sock: socket.Socket{PID: n.NewPID()}},
			{name: "lan1", index: 4, mac: net.HardwareAddr{2, 0, 0, 0, 0, 4}, sock: socket.Socket{PID: n.NewPID()}},
		},
		now:  func() time.Time { return r.now },
		logf: t.Logf,
		send: func(s socket.Socket, to *syscall.SockaddrInet6, b []byte) molecule.Effect {
			return sent{sock: s.PID, to: netip.AddrFrom16(to.Addr), zone: to.ZoneId, msg: b}
		},
		arm: func(s socket.Socket) molecule.Effect { return armed{sock: s.PID} },
	}
	return r
}

// solicitation is a Neighbor Solicitation for target from source, as the
// WAN packet socket delivers it: from the IPv6 header on.
func solicitation(target, source netip.Addr) []byte {
	body, dst := ndproxy.Solicitation(target, net.HardwareAddr{2, 9, 9, 9, 9, 9})
	b := make([]byte, 40+len(body))
	b[0], b[6], b[7] = 0x60, syscall.IPPROTO_ICMPV6, 255
	s, d := source.As16(), dst.As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	copy(b[40:], body)
	return b
}

// advertisement is a LAN host's Neighbor Advertisement for target, as a
// raw ICMPv6 socket delivers it.
func advertisement(target netip.Addr) []byte {
	b, _ := ndproxy.Advertisement(target, solicitor, net.HardwareAddr{2, 8, 8, 8, 8, 8})
	return b
}

func sends(effs []molecule.Effect) []sent {
	var ss []sent
	for _, e := range effs {
		if s, ok := e.(sent); ok {
			ss = append(ss, s)
		}
	}
	return ss
}

func casts(effs []molecule.Effect) []any {
	var cs []any
	for _, e := range effs {
		if c, ok := e.(molecule.Cast); ok && c.To == RoutesName {
			cs = append(cs, c.Req)
		}
	}
	return cs
}

// A WAN Solicitation for an unknown host has every LAN probed; the host's
// Advertisement has the WAN answered and its route installed; the next
// Solicitation for it is answered at once.
func TestProbeConfirmAnswer(t *testing.T) {
	r := newRig(t)
	p := r.p
	st, _, _ := p.Init(proc.PID{})

	next, effs := p.HandleInfo(st, socket.DataMsg{Sock: p.wanRX, Bytes: solicitation(target, solicitor)})
	ss := sends(effs)
	if len(ss) != 2 || ss[0].sock != p.lans[0].sock.PID || ss[1].sock != p.lans[1].sock.PID {
		t.Fatalf("probes %+v, want one per LAN", ss)
	}
	if want := netip.MustParseAddr("ff02::1:ff00:abcd"); ss[0].to != want || ss[0].zone != 3 {
		t.Errorf("probe to %v%%%d, want the Solicited-Node group %v on lan0", ss[0].to, ss[0].zone, want)
	}
	if effs[len(effs)-1] != (armed{sock: p.wanRX.PID}) {
		t.Errorf("the WAN socket not re-armed: %v", effs)
	}
	if again, _ := st.OnWANSolicit(r.now, target, solicitor); again != nil {
		t.Error("the State given was changed")
	}
	st = next

	r.now = r.now.Add(100 * time.Millisecond)
	st, effs = p.HandleInfo(st, socket.DataMsg{Sock: p.lans[1].sock, Bytes: advertisement(target)})
	ss = sends(effs)
	if len(ss) != 1 || ss[0].sock != p.wanTX.PID || ss[0].to != solicitor || ss[0].zone != 2 {
		t.Fatalf("WAN answer %+v, want one to %v", ss, solicitor)
	}
	if cs := casts(effs); len(cs) != 1 || cs[0] != (install{Target: target, Iface: "lan1"}) {
		t.Errorf("route casts %v", cs)
	}

	_, effs = p.HandleInfo(st, socket.DataMsg{Sock: p.wanRX, Bytes: solicitation(target, solicitor)})
	if ss := sends(effs); len(ss) != 1 || ss[0].sock != p.wanTX.PID {
		t.Errorf("a confirmed host's Solicitation: %+v, want an answer at once", ss)
	}
}

// A DAD-style Solicitation, from the unspecified address, is answered to
// all nodes.
func TestAnswerDAD(t *testing.T) {
	r := newRig(t)
	p := r.p
	st, _, _ := p.Init(proc.PID{})
	st, _ = p.HandleInfo(st, socket.DataMsg{Sock: p.wanRX, Bytes: solicitation(target, netip.IPv6Unspecified())})
	_, effs := p.HandleInfo(st, socket.DataMsg{Sock: p.lans[0].sock, Bytes: advertisement(target)})
	if ss := sends(effs); len(ss) != 1 || ss[0].to != netip.MustParseAddr("ff02::1") {
		t.Errorf("DAD answer %+v, want to ff02::1", ss)
	}
}

// An Advertisement answering no probe of ours changes nothing.
func TestStrayAdvertisement(t *testing.T) {
	r := newRig(t)
	p := r.p
	st, _, _ := p.Init(proc.PID{})
	next, effs := p.HandleInfo(st, socket.DataMsg{Sock: p.lans[0].sock, Bytes: advertisement(target)})
	if next != st || len(sends(effs)) != 0 || len(casts(effs)) != 0 {
		t.Errorf("a stray Advertisement: %v", effs)
	}
}

// Sweeping retransmits a probe unanswered, and has a host gone quiet have
// its route removed.
func TestSweep(t *testing.T) {
	r := newRig(t)
	p := r.p
	st, _, _ := p.Init(proc.PID{})
	other := netip.MustParseAddr("2001:db8::beef")
	st, _ = p.HandleInfo(st, socket.DataMsg{Sock: p.wanRX, Bytes: solicitation(target, solicitor)})
	st, _ = p.HandleInfo(st, socket.DataMsg{Sock: p.lans[0].sock, Bytes: advertisement(target)})
	st, _ = p.HandleInfo(st, socket.DataMsg{Sock: p.wanRX, Bytes: solicitation(other, solicitor)})

	r.now = r.now.Add(ndproxy.SweepInterval)
	st, effs := p.HandleInfo(st, sweep{})
	if ss := sends(effs); len(ss) != 2 {
		t.Errorf("retransmitted probes %+v, want one per LAN", ss)
	}
	if _, ok := effs[len(effs)-1].(molecule.StartTimer); !ok {
		t.Errorf("no next sweep: %v", effs)
	}

	r.now = r.now.Add(10 * time.Minute)
	_, effs = p.HandleInfo(st, sweep{})
	if cs := casts(effs); len(cs) != 1 || cs[0] != (remove{Target: target, Iface: "lan0"}) {
		t.Errorf("route casts %v", cs)
	}
}
