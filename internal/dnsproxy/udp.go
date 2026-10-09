package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/net/genudp"
	"github.com/shun159/molecule/proc"
	"golang.org/x/sys/unix"
)

// udpQueryTimeout bounds how long a query waits for one upstream to answer
// before trying the next.
const udpQueryTimeout = 5 * time.Second

// maxInFlight bounds the queries forwarded at once by one listener. Past it,
// queries wait in the kernel, which drops them when its buffer fills -- the
// client's resolver retries, as it would for any lost datagram.
const maxInFlight = 256

// maxUDPMessageBytes is generous enough for any EDNS0 (RFC 6891) answer a
// real-world resolver sends -- this package never parses a message, so
// there's no reason to size the buffer down to plain DNS's traditional
// 512-byte limit and risk silently truncating a larger one.
const maxUDPMessageBytes = 65535

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

// udpListener serves DNS over UDP on one address.
type udpListener struct {
	addr      netip.AddrPort
	upstreams []netip.AddrPort
	timeout   time.Duration // per upstream
}

// start binds the listener's socket and starts the listener with it. The
// socket is bound first, and passive until the listener owns it, so the
// start fails on an address that cannot be bound, and nothing is read before
// there is someone to hand it to.
func (u udpListener) start(ctx context.Context, parent *proc.Self) (proc.PID, error) {
	sock, err := u.open(ctx, parent)
	if err != nil {
		return proc.PID{}, err
	}
	l := listener{sock: sock, upstreams: u.upstreams, timeout: u.timeout}
	pid, err := genserver.Child(l).StartLink(ctx, parent)
	if err == nil {
		err = sock.ControllingProcess(ctx, parent, pid)
		if err == nil {
			err = sock.SetActive(ctx, parent, genudp.N(maxInFlight))
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

// open binds the listener's socket, owned by parent, waiting out a
// tentative address.
func (u udpListener) open(ctx context.Context, parent *proc.Self) (genudp.Socket, error) {
	addr := u.addr.String()
	for attempt := 0; ; attempt++ {
		sock, err := genudp.Open(ctx, parent, addr, genudp.Options{})
		if err == nil {
			return sock, nil
		}
		if !errors.Is(err, unix.EADDRNOTAVAIL) || attempt >= bindRetries {
			return genudp.Socket{}, fmt.Errorf("dnsproxy: listening on %s/udp: %w", addr, err)
		}
		select {
		case <-ctx.Done():
			return genudp.Socket{}, ctx.Err()
		case <-time.After(bindRetryInterval):
		}
	}
}

// listener is the UDP listener of an address: it owns the socket and
// forwards each query in an Async of its own, so one slow or unresponsive
// upstream never holds up the next query. Its state is the key of the next
// query.
//
// The socket's active mode is its flow control: it is armed for as many
// queries as there are free slots, maxInFlight, and re-armed by one as each
// query's Async ends.
type listener struct {
	genserver.Default[uint64]
	sock      genudp.Socket
	upstreams []netip.AddrPort
	timeout   time.Duration
}

// answer is the outcome of forwarding a query: the answer to relay to the
// client.
type answer struct {
	to   netip.AddrPort
	data []byte
}

func (l listener) HandleInfo(next uint64, msg any) (uint64, []molecule.Effect) {
	switch m := msg.(type) {
	case genudp.DataMsg:
		return next + 1, molecule.Do(molecule.Async{Key: next, Run: l.forward(m.From, m.Bytes)})
	case molecule.AsyncResult:
		if a, ok := m.Value.(answer); ok {
			return next, molecule.Do(l.sock.SendActiveEffect(a.to, a.data, genudp.N(1)))
		}
		return next, molecule.Do(l.sock.SetActiveEffect(genudp.N(1)))
	case genudp.ErrorMsg:
		return next, molecule.Do(molecule.Stop{Reason: fmt.Errorf("dnsproxy: reading %s: %w", l.sock.LocalAddr, m.Err)})
	case genudp.ClosedMsg:
		return next, molecule.Do(molecule.Stop{Reason: fmt.Errorf("dnsproxy: %s closed", l.sock.LocalAddr)})
	}
	// A SendErrorMsg is an answer lost, as a datagram may be: the client's
	// resolver retries.
	return next, nil
}

// forward is the Run of the Async forwarding query from client: it tries
// each upstream in order, and returns the first answer, or none -- the query
// dropped, for the client's own resolver to retry per its usual
// timeout/retransmission behavior, the same as if this proxy weren't in the
// path at all.
func (l listener) forward(client netip.AddrPort, query []byte) func(context.Context) (any, error) {
	return func(ctx context.Context) (any, error) {
		for _, upstream := range l.upstreams {
			data, err := ask(ctx, upstream, query, l.timeout)
			if err == nil {
				return answer{to: client, data: data}, nil
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, nil
	}
}

// ask sends query to upstream over a fresh socket (one per query, not pooled:
// DNS-over-UDP is a single datagram round trip, and a dedicated socket means
// the answer can't be confused with any other concurrent query's -- connected,
// it takes datagrams from upstream alone) and returns its answer, bounded by
// timeout and ctx.
func ask(ctx context.Context, upstream netip.AddrPort, query []byte, timeout time.Duration) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", upstream.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, maxUDPMessageBytes)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}
