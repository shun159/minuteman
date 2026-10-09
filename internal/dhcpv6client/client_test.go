package dhcpv6client

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/proc"
)

var (
	clientDUID = dhcpv6.NewDUIDLL(dhcpv6.HardwareTypeEthernet, net.HardwareAddr{2, 0, 0, 0, 0, 1})
	serverDUID = dhcpv6.NewDUIDLL(dhcpv6.HardwareTypeEthernet, net.HardwareAddr{2, 0, 0, 0, 0, 2})
)

// server is a fake DHCPv6 server on the loopback: it records what it gets,
// and answers what answer says to, with what it returns.
type server struct {
	conn *net.UDPConn

	mu  sync.Mutex
	got []*dhcpv6.Message
}

func newServer(t *testing.T, answer func(n int, m *dhcpv6.Message) []*dhcpv6.Message) *server {
	t.Helper()
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	t.Cleanup(func() { conn.Close() })
	s := &server{conn: conn}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			m, err := dhcpv6.ParseMessage(buf[:n])
			if err != nil {
				continue
			}
			s.mu.Lock()
			s.got = append(s.got, m)
			k := len(s.got)
			s.mu.Unlock()
			for _, r := range answer(k, m) {
				b, _ := r.MarshalBinary()
				conn.WriteToUDPAddrPort(b, from)
			}
		}
	}()
	return s
}

func (s *server) addr() netip.AddrPort { return s.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

func (s *server) messages() []*dhcpv6.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*dhcpv6.Message(nil), s.got...)
}

// reply is the valid answer to m, of type typ.
func reply(m *dhcpv6.Message, typ dhcpv6.MessageType) *dhcpv6.Message {
	return &dhcpv6.Message{Type: typ, XID: m.XID, Options: dhcpv6.Options{
		{Code: dhcpv6.OptionServerID, Data: serverDUID},
		dhcpv6.NewClientIDOption(clientDUID),
	}}
}

func always(n int, m *dhcpv6.Message) []*dhcpv6.Message {
	return []*dhcpv6.Message{reply(m, dhcpv6.MessageTypeReply)}
}

func never(int, *dhcpv6.Message) []*dhcpv6.Message { return nil }

// start starts a client talking to srv, and returns it.
func start(t *testing.T, srv *server) Client {
	t.Helper()
	n := proc.NewNode("")
	cfg := Config{
		Iface:    "test",
		bind:     netip.AddrPortFrom(netip.IPv6Loopback(), 0),
		server:   srv.addr(),
		clientID: clientDUID,
	}
	sup, err := supervisor.Start(t.Context(), n, supervisor.Spec{Children: []supervisor.ChildSpec{ChildSpec(cfg)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { supervisor.Stop(context.Background(), n, sup) })
	return NewClient(n, "test")
}

// fast is an exchange expecting a Reply, retransmitting every 20ms or so.
func fast(typ dhcpv6.MessageType, mrc int) dhcpv6.Exchange {
	return dhcpv6.Exchange{
		Type:   typ,
		Expect: dhcpv6.MessageTypeReply,
		Timing: dhcpv6.Timing{IRT: 20 * time.Millisecond, MRT: 20 * time.Millisecond, MRC: mrc},
	}
}

func elapsed(m *dhcpv6.Message) time.Duration {
	o, _ := m.Options.Get(dhcpv6.OptionElapsedTime)
	return time.Duration(binary.BigEndian.Uint16(o.Data)) * 10 * time.Millisecond
}

func TestExchange(t *testing.T) {
	srv := newServer(t, always)
	c := start(t, srv)
	got, err := dhcpv6.InformationRequest(t.Context(), c, []uint16{dhcpv6.OptionDNSServers})
	if err != nil {
		t.Fatal(err)
	}
	sent := srv.messages()
	if got.Type != dhcpv6.MessageTypeReply || len(sent) != 1 || got.XID != sent[0].XID {
		t.Fatalf("reply %v to %d message(s)", got, len(sent))
	}
	if id, _ := sent[0].Options.ClientID(); string(id) != string(clientDUID) {
		t.Errorf("client ID %x", id)
	}
}

// Unanswered, the message is sent again, same transaction, later elapsed
// time.
func TestRetransmit(t *testing.T) {
	srv := newServer(t, func(n int, m *dhcpv6.Message) []*dhcpv6.Message {
		if n < 3 {
			return nil
		}
		return always(n, m)
	})
	c := start(t, srv)
	if _, err := c.Exchange(t.Context(), fast(dhcpv6.MessageTypeRenew, 0)); err != nil {
		t.Fatal(err)
	}
	sent := srv.messages()
	if len(sent) != 3 {
		t.Fatalf("%d messages sent, want 3", len(sent))
	}
	for i, m := range sent {
		if m.XID != sent[0].XID {
			t.Errorf("message %d in another transaction", i)
		}
	}
	if elapsed(sent[0]) != 0 || elapsed(sent[1]) == 0 || elapsed(sent[2]) <= elapsed(sent[1]) {
		t.Errorf("elapsed times %v %v %v", elapsed(sent[0]), elapsed(sent[1]), elapsed(sent[2]))
	}
}

func TestExhausted(t *testing.T) {
	srv := newServer(t, never)
	c := start(t, srv)
	if _, err := c.Exchange(t.Context(), fast(dhcpv6.MessageTypeRequest, 3)); !errors.Is(err, dhcpv6.ErrExhausted) {
		t.Fatalf("Exchange = %v, want ErrExhausted", err)
	}
	if n := len(srv.messages()); n != 3 {
		t.Errorf("%d messages sent, want 3", n)
	}
}

// What does not answer the exchange is ignored, and the exchange goes on.
func TestIgnoresOthers(t *testing.T) {
	srv := newServer(t, func(n int, m *dhcpv6.Message) []*dhcpv6.Message {
		other := reply(m, dhcpv6.MessageTypeReply)
		other.XID[0]++
		anonymous := reply(m, dhcpv6.MessageTypeReply)
		anonymous.Options = anonymous.Options[1:] // no server ID
		return []*dhcpv6.Message{other, anonymous, reply(m, dhcpv6.MessageTypeAdvertise), reply(m, dhcpv6.MessageTypeReply)}
	})
	c := start(t, srv)
	got, err := c.Exchange(t.Context(), fast(dhcpv6.MessageTypeRenew, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Options.ServerID(); !ok || got.Type != dhcpv6.MessageTypeReply {
		t.Errorf("took %+v", got)
	}
	if n := len(srv.messages()); n != 1 {
		t.Errorf("%d messages sent, want 1", n)
	}
}

// Exchanges run one at a time: the second starts once the first is answered.
func TestOneAtATime(t *testing.T) {
	srv := newServer(t, func(n int, m *dhcpv6.Message) []*dhcpv6.Message {
		if n%2 == 1 {
			return nil // each exchange answered on its second message
		}
		return always(n, m)
	})
	c := start(t, srv)
	var wg sync.WaitGroup
	for _, typ := range []dhcpv6.MessageType{dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind} {
		wg.Go(func() {
			if _, err := c.Exchange(t.Context(), fast(typ, 0)); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	sent := srv.messages()
	if len(sent) != 4 || sent[0].XID != sent[1].XID || sent[2].XID != sent[3].XID || sent[1].XID == sent[2].XID {
		t.Errorf("messages interleaved: %d sent", len(sent))
	}
}

// An exchange given up on is abandoned, letting the next run.
func TestCancel(t *testing.T) {
	srv := newServer(t, func(n int, m *dhcpv6.Message) []*dhcpv6.Message {
		if m.Type == dhcpv6.MessageTypeRenew {
			return nil
		}
		return always(n, m)
	})
	c := start(t, srv)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	begin := time.Now()
	if _, err := c.Exchange(ctx, fast(dhcpv6.MessageTypeRenew, 0)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Exchange = %v, want DeadlineExceeded", err)
	}
	if d := time.Since(begin); d > time.Second {
		t.Errorf("gave up after %v", d)
	}
	if _, err := c.Exchange(t.Context(), fast(dhcpv6.MessageTypeRebind, 0)); err != nil {
		t.Fatal(err)
	}
}

// An exchange given up on while waiting its turn never runs.
func TestCancelWaiting(t *testing.T) {
	srv := newServer(t, func(n int, m *dhcpv6.Message) []*dhcpv6.Message {
		if m.Type == dhcpv6.MessageTypeRenew && n < 10 {
			return nil // the first exchange runs a while
		}
		return always(n, m)
	})
	c := start(t, srv)
	first := make(chan error, 1)
	go func() {
		_, err := c.Exchange(t.Context(), fast(dhcpv6.MessageTypeRenew, 0))
		first <- err
	}()
	time.Sleep(30 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, err := c.Exchange(ctx, fast(dhcpv6.MessageTypeRebind, 0)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting Exchange = %v, want DeadlineExceeded", err)
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exchange(t.Context(), fast(dhcpv6.MessageTypeRelease, 0)); err != nil {
		t.Fatal(err)
	}
	for _, m := range srv.messages() {
		if m.Type == dhcpv6.MessageTypeRebind {
			t.Fatal("the abandoned exchange ran")
		}
	}
}
