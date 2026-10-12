package dhcpv4server

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv4"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/gensim"
	"github.com/shun159/molecule/kvs"
	"github.com/shun159/molecule/net/socket"
	"github.com/shun159/molecule/proc"
)

func openLeases(t *testing.T, dir string) *Leases {
	t.Helper()
	leases, err := OpenLeases(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { leases.Close() })
	return leases
}

func withType(msg *dhcpv4.Message, mt dhcpv4.MessageType, opts ...dhcpv4.Option) *dhcpv4.Message {
	msg.Options = append(dhcpv4.Options{{Code: dhcpv4.OptMessageType, Data: []byte{byte(mt)}}}, opts...)
	return msg
}

// selecting is the REQUEST accepting this server's offer of ip.
func selecting(ip netip.Addr) *dhcpv4.Message {
	return withType(discover(), dhcpv4.Request,
		dhcpv4.Option{Code: dhcpv4.OptRequestedIP, Data: ip.AsSlice()},
		dhcpv4.Option{Code: dhcpv4.OptServerID, Data: serverIP.AsSlice()})
}

// initReboot is the REQUEST of a client rebooting with ip cached: no
// server identifier.
func initReboot(ip netip.Addr) *dhcpv4.Message {
	return withType(discover(), dhcpv4.Request, dhcpv4.Option{Code: dhcpv4.OptRequestedIP, Data: ip.AsSlice()})
}

// The REQUEST committing a lease puts it in the table and holds its ACK
// until it is on disk, taking the next request meanwhile; an offer writes
// nothing; a RELEASE deletes the lease.
func TestKeepEffects(t *testing.T) {
	s, pool := newServer(t)
	s.leases = openLeases(t, t.TempDir())

	pool, to, frame, _ := s.answer(pool, request(discover()))
	reply, _ := dhcpv4.Parse(frame[28:])
	ip := reply.YIAddr
	if _, effs := s.HandleInfo(pool, socket.DataMsg{Bytes: request(discover())}); !reflect.DeepEqual(effs, molecule.Do(s.sock.SendActiveEffect(to, frame, socket.Once))) {
		t.Errorf("an offer: %v", effs)
	}

	next, to, frame, id := s.answer(pool, request(selecting(ip)))
	l, _ := next.Committed(id, s.now())
	got, effs := s.HandleInfo(pool, socket.DataMsg{Bytes: request(selecting(ip))})
	want := molecule.Do(s.sock.SetActiveEffect(socket.Once), s.leases.PutEffect(id, l, &held{to, frame}))
	if !reflect.DeepEqual(effs, want) {
		t.Errorf("the commit: %v, want %v", effs, want)
	}
	if _, effs := s.HandleInfo(got, durable(&held{to, frame})); !reflect.DeepEqual(effs, molecule.Do(s.sock.SendEffect(to, frame))) {
		t.Errorf("once durable: %v", effs)
	}

	release := withType(discover(), dhcpv4.Release, dhcpv4.Option{Code: dhcpv4.OptServerID, Data: serverIP.AsSlice()})
	release.CIAddr = ip
	if _, effs := s.HandleInfo(got, socket.DataMsg{Bytes: request(release)}); !reflect.DeepEqual(effs, molecule.Do(s.leases.DeleteEffect(id, nil), s.sock.SetActiveEffect(socket.Once))) {
		t.Errorf("a release: %v", effs)
	}
}

// recorder keeps what it is sent, standing for the socket process.
type recorder struct {
	genserver.Default[[]any]
}

func (recorder) HandleInfo(msgs []any, msg any) ([]any, []molecule.Effect) {
	return append(msgs, msg), nil
}

// sent returns the DHCP replies the server sent through rec.
func sent(t *testing.T, s *gensim.Sim, rec proc.PID) []*dhcpv4.Message {
	t.Helper()
	msgs, _ := gensim.State[[]any](s, rec)
	var replies []*dhcpv4.Message
	for _, m := range msgs {
		data := reflect.ValueOf(m).FieldByName("Data")
		if !data.IsValid() {
			continue // asking for the next request
		}
		reply, err := dhcpv4.Parse(data.Bytes()[28:])
		if err != nil {
			t.Fatal(err)
		}
		replies = append(replies, reply)
	}
	return replies
}

// A lease granted is kept across a restart: the server started again with
// the table ACKs the INIT-REBOOT of the client for its address at once,
// where one without would stay silent.
func TestLeaseKeptAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	leases := openLeases(t, dir)
	start := func(sim *gensim.Sim) (proc.PID, proc.PID) {
		rec, err := gensim.Spawn(sim, genserver.Gen(recorder{}), nil)
		if err != nil {
			t.Fatal(err)
		}
		s, pool := newServer(t) // s.now is the clock of sim, once spawned
		if err := restore(pool, leases, sim.Now()); err != nil {
			t.Fatal(err)
		}
		s.pool, s.leases, s.sock = pool, leases, socket.Socket{PID: rec}
		pid, err := gensim.Spawn(sim, genserver.Gen(s), nil)
		if err != nil {
			t.Fatal(err)
		}
		return pid, rec
	}

	sim := gensim.New(1)
	pid, rec := start(sim)
	sim.Send(pid, socket.DataMsg{Bytes: request(discover())})
	sim.RunUntilIdle()
	offer := sent(t, sim, rec)
	if len(offer) != 1 {
		t.Fatalf("%d replies to a DISCOVER", len(offer))
	}
	ip := offer[0].YIAddr
	sim.Send(pid, socket.DataMsg{Bytes: request(selecting(ip))})
	sim.RunUntilIdle()
	if r := sent(t, sim, rec); len(r) != 2 || r[1].YIAddr != ip {
		t.Fatalf("replies %v", r)
	} else if mt, _ := r[1].Options.MessageType(); mt != dhcpv4.ACK {
		t.Fatalf("reply %v to the REQUEST", mt)
	}
	if l, ok := leases.Get(string(clientHW)); !ok || l.IP != ip {
		t.Fatalf("the table holds %+v %v", l, ok)
	}

	// The CPE restarts: a new run, a new server, the same table.
	sim = gensim.New(2)
	pid, rec = start(sim)
	sim.Send(pid, socket.DataMsg{Bytes: request(initReboot(ip))})
	sim.RunUntilIdle()
	r := sent(t, sim, rec)
	if len(r) != 1 || r[0].YIAddr != ip {
		t.Fatalf("replies to the INIT-REBOOT: %v", r)
	}
	if mt, _ := r[0].Options.MessageType(); mt != dhcpv4.ACK {
		t.Fatalf("reply %v to the INIT-REBOOT", mt)
	}
}

// The server deletes a lease from the table once it expires, by its clock,
// and keeps one renewed.
func TestLeaseExpires(t *testing.T) {
	leases := openLeases(t, t.TempDir())
	sim := gensim.New(1)
	rec, err := gensim.Spawn(sim, genserver.Gen(recorder{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, pool := newServer(t)
	s.pool, s.leases, s.sock = pool, leases, socket.Socket{PID: rec}
	pid, err := gensim.Spawn(sim, genserver.Gen(s), nil)
	if err != nil {
		t.Fatal(err)
	}
	grant := func() netip.Addr {
		t.Helper()
		sim.Send(pid, socket.DataMsg{Bytes: request(discover())})
		sim.RunUntilIdle()
		r := sent(t, sim, rec)
		ip := r[len(r)-1].YIAddr
		sim.Send(pid, socket.DataMsg{Bytes: request(selecting(ip))})
		sim.RunUntilIdle()
		if _, ok := leases.Get(string(clientHW)); !ok {
			t.Fatal("no lease in the table")
		}
		return ip
	}
	grant()

	// Renewed halfway, the lease outlives its first expiry.
	sim.Advance(cfg.LeaseTime / 2)
	grant()
	sim.Advance(cfg.LeaseTime/2 + 2*expireEvery)
	if _, ok := leases.Get(string(clientHW)); !ok {
		t.Fatal("a renewed lease deleted")
	}
	sim.Advance(cfg.LeaseTime / 2)
	if l, ok := leases.Get(string(clientHW)); ok {
		t.Fatalf("a lease kept past its expiry: %+v", l)
	}
}

// Restoring drops the leases that expired while the CPE was down.
func TestRestoreDropsExpired(t *testing.T) {
	leases := openLeases(t, t.TempDir())
	s, pool := newServer(t)
	ip := netip.MustParseAddr("192.168.1.50")
	leases.Put("gone", dhcpv4.Lease{IP: ip, Expiry: s.now().Add(-time.Minute)})
	leases.Put("here", dhcpv4.Lease{IP: ip.Next(), Expiry: s.now().Add(time.Hour)})
	if err := restore(pool, leases, s.now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := leases.Get("gone"); ok {
		t.Error("an expired lease kept")
	}
	if got, ok := pool.Binding("here", s.now()); !ok || got != ip.Next() {
		t.Errorf("restored %v %v", got, ok)
	}
}

func durable(h *held) kvs.Durable { return kvs.Durable{Tag: h} }
