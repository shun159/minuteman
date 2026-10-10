package radvd

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/shun159/miniteman/pkg/routeradvert"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/net/socket"
	"github.com/shun159/molecule/proc"
)

// Effects the advertiser under test returns in place of sending to and
// arming its socket.
type (
	sentRA struct {
		molecule.Extension
		ra []byte
	}
	armed struct{ molecule.Extension }
)

var cfg = routeradvert.Config{
	Prefix:            netip.MustParsePrefix("2001:db8:1::/64"),
	OnLink:            true,
	ValidLifetime:     time.Hour,
	PreferredLifetime: 30 * time.Minute,
}

func testAdvertiser() advertiser {
	return advertiser{
		iface:  "lan0",
		mac:    net.HardwareAddr{2, 0, 0, 0, 0, 1},
		seed:   [2]uint64{1, 2},
		sendRA: func(b []byte) molecule.Effect { return sentRA{ra: b} },
		armRS:  armed{},
	}
}

func start(t *testing.T, a advertiser) state {
	t.Helper()
	s, _, err := a.Init(proc.PID{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// lifetimes are the RouterLifetimes of the RAs effs send.
func lifetimes(effs []molecule.Effect) []time.Duration {
	var ls []time.Duration
	for _, e := range effs {
		if s, ok := e.(sentRA); ok {
			ls = append(ls, time.Duration(binary.BigEndian.Uint16(s.ra[6:8]))*time.Second)
		}
	}
	return ls
}

// timer is the StartTimer of key in effs.
func timer(effs []molecule.Effect, key any) (molecule.StartTimer, bool) {
	for _, e := range effs {
		if st, ok := e.(molecule.StartTimer); ok && st.Key == key {
			return st, true
		}
	}
	return molecule.StartTimer{}, false
}

var rs = socket.DataMsg{Bytes: []byte{133, 0, 0, 0, 0, 0, 0, 0}}

// Idle until given a Config: a Solicitation then is not answered.
func TestIdleUntilConfigured(t *testing.T) {
	a := testAdvertiser()
	s := start(t, a)
	s, effs := a.HandleInfo(s, rs)
	if len(effs) != 1 || effs[0] != (armed{}) {
		t.Errorf("idle, a Solicitation drew %v", effs)
	}
	if effs := a.Terminate(s, nil); effs != nil {
		t.Errorf("idle, terminating sends %v", effs)
	}
}

// Configured, it advertises at once, then on the initial burst's cadence,
// never two RAs within MinDelayBetweenRAs.
func TestAdvertise(t *testing.T) {
	a := testAdvertiser()
	s := start(t, a)
	s, effs := a.HandleCast(s, advertise{cfg})
	if st, ok := timer(effs, unsolicited{}); !ok || st.After != 0 {
		t.Fatalf("configured: %v", effs)
	}
	s, effs = a.HandleInfo(s, unsolicited{})
	if ls := lifetimes(effs); len(ls) != 1 || ls[0] != routeradvert.AdvDefaultLifetime {
		t.Errorf("unsolicited RA lifetimes %v", ls)
	}
	if st, ok := timer(effs, quiet{}); !ok || st.After != routeradvert.MinDelayBetweenRAs {
		t.Errorf("no quiet timer: %v", effs)
	}
	if st, ok := timer(effs, unsolicited{}); !ok || st.After > 16*time.Second {
		t.Errorf("next unsolicited %v, want within the initial burst's 16s", st.After)
	}

	// A Solicitation within MinDelayBetweenRAs is answered by the RA just
	// sent; once quiet, it gets an answer of its own, delayed.
	s, effs = a.HandleInfo(s, rs)
	if _, ok := timer(effs, reply{}); ok || len(lifetimes(effs)) > 0 {
		t.Errorf("answered a Solicitation while recent: %v", effs)
	}
	s, _ = a.HandleInfo(s, quiet{})
	s, effs = a.HandleInfo(s, rs)
	st, ok := timer(effs, reply{})
	if !ok || st.After > 500*time.Millisecond {
		t.Fatalf("Solicitation answered after %v", st.After)
	}
	_, effs = a.HandleInfo(s, reply{})
	if ls := lifetimes(effs); len(ls) != 1 {
		t.Errorf("reply RAs %v", ls)
	}
}

// A changed Config is advertised at once, or once quiet if an RA just went;
// the same Config changes nothing.
func TestUpdate(t *testing.T) {
	a := testAdvertiser()
	s := start(t, a)
	s, _ = a.HandleCast(s, advertise{cfg})
	s, _ = a.HandleInfo(s, unsolicited{})
	s, effs := a.HandleCast(s, advertise{cfg})
	if len(effs) != 0 {
		t.Errorf("same Config: %v", effs)
	}
	changed := cfg
	changed.ValidLifetime = 2 * time.Hour
	s, effs = a.HandleCast(s, advertise{changed})
	if len(effs) != 0 || !s.pending {
		t.Fatalf("changed while recent: %v, pending %v", effs, s.pending)
	}
	s, effs = a.HandleInfo(s, quiet{})
	if st, ok := timer(effs, unsolicited{}); !ok || st.After != 0 || s.pending {
		t.Errorf("once quiet: %v", effs)
	}
	if s.cfg != changed {
		t.Errorf("advertising %+v", s.cfg)
	}
}

// The steady-state cadence varies: the generator advances.
func TestCadenceVaries(t *testing.T) {
	a := testAdvertiser()
	s := start(t, a)
	s, _ = a.HandleCast(s, advertise{cfg})
	s.sent = 10 // steady state
	seen := map[time.Duration]bool{}
	for range 5 {
		var effs []molecule.Effect
		s, effs = a.HandleInfo(s, unsolicited{})
		st, _ := timer(effs, unsolicited{})
		seen[st.After] = true
		s, _ = a.HandleInfo(s, quiet{})
	}
	if len(seen) < 2 {
		t.Errorf("the same interval every time: %v", seen)
	}
}

func TestSendErrors(t *testing.T) {
	a := testAdvertiser()
	s := start(t, a)
	s, _ = a.HandleCast(s, advertise{cfg})
	s, _ = a.HandleInfo(s, unsolicited{})
	s, effs := a.HandleInfo(s, socket.SendErrorMsg{Err: syscall.EADDRNOTAVAIL})
	if st, ok := timer(effs, unsolicited{}); !ok || st.After != routeradvert.TentativeRetryInterval || s.sent != 0 {
		t.Errorf("tentative: %v, sent %d", effs, s.sent)
	}
	_, effs = a.HandleInfo(s, socket.SendErrorMsg{Err: errors.New("boom")})
	if len(effs) != 1 {
		t.Fatalf("send failure: %v", effs)
	}
	if _, ok := effs[0].(molecule.Stop); !ok {
		t.Errorf("send failure: %v", effs)
	}
}

// Terminating withdraws the router: an RA with RouterLifetime 0.
func TestTerminate(t *testing.T) {
	a := testAdvertiser()
	s := start(t, a)
	s, _ = a.HandleCast(s, advertise{cfg})
	if ls := lifetimes(a.Terminate(s, nil)); len(ls) != 1 || ls[0] != 0 {
		t.Errorf("final RA lifetimes %v", ls)
	}
}
