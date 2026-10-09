package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/shun159/molecule/net/genudp"
	"github.com/shun159/molecule/proc"
	"golang.org/x/sys/unix"
)

// udpQueryTimeout bounds how long a forwarder waits for one upstream to
// answer before trying the next.
const udpQueryTimeout = 5 * time.Second

// maxInFlight bounds the queries forwarded at once by one listener. Past it,
// queries wait in the kernel, which drops them when its buffer fills -- the
// client's resolver retries, as it would for any lost datagram.
const maxInFlight = 256

// bindRetries/bindRetryInterval bound how long a listener waits out an
// EADDRNOTAVAIL when binding a LAN link-local address: the kernel returns
// that while the address is still DAD-tentative, which right after XDP
// attach bounces the LAN link (see routeradvert's tentativeRetryInterval) it
// briefly is. ~10 * 1s covers several DAD cycles; any *other* bind error
// (e.g. EADDRINUSE, port 53 already taken) fails at once, so a real
// misconfiguration surfaces at once.
const (
	bindRetries       = 10
	bindRetryInterval = time.Second
)

// udpListener serves DNS over UDP on one address: it owns the socket and
// hands each query to a forwarder process of its own, so one slow or
// unresponsive upstream never holds up the next query.
//
// It is written against proc rather than as a behaviour because it starts a
// process per query. The socket's active mode is its flow control: it is
// armed for as many queries as there are free forwarder slots, and re-armed
// by one as each forwarder exits.
type udpListener struct {
	addr      netip.AddrPort
	upstreams []netip.AddrPort
	timeout   time.Duration // per upstream
}

func (u udpListener) start(ctx context.Context, parent *proc.Self) (proc.PID, error) {
	return parent.StartLink(ctx, u.run)
}

func (u udpListener) run(s *proc.Self) error {
	sock, err := u.open(s)
	if err != nil {
		s.InitAck(err)
		return err
	}
	s.InitAck(nil)
	s.SetLabel("dnsproxy udp " + u.addr.String())
	// Trapping exits: forwarders are linked, so that they end with the
	// listener, and their exits free their slots.
	s.TrapExit(true)
	parent := s.Parent()
	for {
		msg, err := s.Receive(context.Background())
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case genudp.DataMsg:
			f := forwarder{client: sock, from: m.From, query: m.Bytes, upstreams: u.upstreams, timeout: u.timeout}
			s.SpawnLink(f.run)
		case genudp.ErrorMsg:
			return fmt.Errorf("dnsproxy: reading %s: %w", u.addr, m.Err)
		case genudp.ClosedMsg:
			return fmt.Errorf("dnsproxy: %s closed", u.addr)
		case proc.ExitMsg:
			if m.From == parent {
				return m.Reason
			}
			if err := sock.SetActive(context.Background(), s, genudp.N(1)); err != nil {
				return err
			}
		}
	}
}

// open binds the listener's socket, waiting out a tentative address.
func (u udpListener) open(s *proc.Self) (genudp.Socket, error) {
	addr := u.addr.String()
	for attempt := 0; ; attempt++ {
		sock, err := genudp.Open(s.Context(), s, addr, genudp.Options{Active: genudp.N(maxInFlight)})
		if err == nil {
			return sock, nil
		}
		if !errors.Is(err, unix.EADDRNOTAVAIL) || attempt >= bindRetries {
			return genudp.Socket{}, fmt.Errorf("dnsproxy: listening on %s/udp: %w", addr, err)
		}
		time.Sleep(bindRetryInterval)
	}
}

// forwarder forwards one query: it tries each upstream in order over a fresh
// socket of its own (one per query, not pooled: DNS-over-UDP is a single
// datagram round trip, and a dedicated socket means a response can't be
// confused with any other concurrent query's), and relays the first answer
// back to the client through the listener's socket. If every upstream
// fails, the query is dropped -- the client's own resolver retries per its
// usual timeout/retransmission behavior, the same as if this proxy weren't
// in the path at all.
type forwarder struct {
	client    genudp.Socket
	from      netip.AddrPort
	query     []byte
	upstreams []netip.AddrPort
	timeout   time.Duration
}

func (f forwarder) run(s *proc.Self) error {
	for _, upstream := range f.upstreams {
		answer, err := ask(s, upstream, f.query, f.timeout)
		if err != nil {
			continue
		}
		f.client.Send(context.Background(), s, f.from, answer)
		return nil
	}
	return nil
}

// ask sends query to upstream and returns its answer, bounded by timeout.
// Datagrams from anywhere else are ignored, as a connected socket would.
func ask(s *proc.Self, upstream netip.AddrPort, query []byte, timeout time.Duration) ([]byte, error) {
	local := "[::]:0"
	if upstream.Addr().Is4() {
		local = "0.0.0.0:0"
	}
	sock, err := genudp.Open(s.Context(), s, local, genudp.Options{})
	if err != nil {
		return nil, err
	}
	defer sock.Close(context.Background(), s)

	ctx, cancel := context.WithTimeout(s.Context(), timeout)
	defer cancel()
	if err := sock.Send(ctx, s, upstream, query); err != nil {
		return nil, err
	}
	for {
		from, answer, err := sock.Recv(ctx, s)
		if err != nil {
			return nil, err
		}
		if from == upstream {
			return answer, nil
		}
	}
}
