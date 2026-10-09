package dhcpv6client

import (
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genstatem"
	"github.com/shun159/molecule/net/genudp"
	"github.com/shun159/molecule/proc"
)

// Phase is the state of the client.
type Phase int

const (
	// Idle runs no exchange; the next request starts one.
	Idle Phase = iota
	// Delaying waits out the random delay before an exchange's first
	// transmission.
	Delaying
	// Waiting has sent the exchange's message, and waits for an answer
	// until its retransmission timeout.
	Waiting
)

func (p Phase) String() string {
	switch p {
	case Idle:
		return "idle"
	case Delaying:
		return "delaying"
	case Waiting:
		return "waiting"
	}
	return "unknown"
}

// The request to the client, and the reply.
type (
	exchangeReq struct{ X dhcpv6.Exchange }

	exchangeRep struct {
		Msg *dhcpv6.Message
		Err error
	}
)

// Messages of the state timeouts.
type (
	transmit   struct{} // Delaying: the delay is over
	retransmit struct{} // Waiting: no answer within the timeout
)

// machine runs the DHCPv6 exchanges of one interface, one at a time, over
// the socket it owns: RFC 3315 §14's transmission and retransmission, the
// matching and validation of what comes back. It is pure: it returns the
// datagrams to send as effects, and draws its randomness (transaction IDs,
// jitter) from a generator kept in its data.
type machine struct {
	sock     genudp.Socket
	server   netip.AddrPort
	clientID dhcpv6.DUID
	seed     [2]uint64
}

// data is the client's data.
type data struct {
	rng rand.PCG

	// The exchange running, outside Idle.
	cur exchange
}

type exchange struct {
	from    molecule.From
	x       dhcpv6.Exchange
	xid     dhcpv6.TransactionID
	rt      time.Duration // the current retransmission timeout
	elapsed time.Duration // since the first transmission
	sent    int           // transmissions so far
}

func (m machine) Init(proc.PID) (Phase, data, []molecule.Effect, error) {
	return Idle, data{rng: *rand.NewPCG(m.seed[0], m.seed[1])}, nil, nil
}

func (m machine) HandleEvent(st Phase, d data, ev genstatem.Event) (Phase, data, []molecule.Effect) {
	switch e := ev.(type) {
	case genstatem.Call:
		req, ok := e.Req.(exchangeReq)
		if !ok {
			break
		}
		// One at a time: the others wait, postponed. One whose caller
		// gives up meanwhile is dropped (see molecule.CallAbandoned).
		if st != Idle {
			return st, d, molecule.Do(genstatem.Postpone{})
		}
		return m.start(d, req, e.From)

	case genstatem.StateTimeout:
		switch e.Msg.(type) {
		case transmit:
			return m.send(d)
		case retransmit:
			if d.cur.x.Timing.MRC != 0 && d.cur.sent >= d.cur.x.Timing.MRC {
				return m.finish(d, nil, dhcpv6.ErrExhausted)
			}
			r := rand.New(&d.rng)
			d.cur.elapsed += d.cur.rt
			d.cur.rt = dhcpv6.NextRT(d.cur.rt, d.cur.x.Timing.MRT, r)
			return m.send(d)
		}

	case genstatem.Info:
		switch msg := e.Msg.(type) {
		case molecule.CallAbandoned:
			// The caller of the exchange running gave up: on to the next.
			if st != Idle && msg.From == d.cur.from {
				d.cur = exchange{}
				return Idle, d, nil
			}
		case genudp.DataMsg:
			if st != Waiting {
				return st, d, nil
			}
			reply, err := dhcpv6.ParseMessage(msg.Bytes)
			if err == nil && d.cur.x.Answers(reply, d.cur.xid, m.clientID) {
				return m.finish(d, reply, nil)
			}
			// Not ours, or malformed: keep waiting.
			return st, d, molecule.Do(m.sock.SetActiveEffect(genudp.Once))
		case genudp.ErrorMsg:
			return st, d, molecule.Do(molecule.Stop{Reason: msg.Err})
		case genudp.ClosedMsg:
			return st, d, molecule.Do(molecule.Stop{Reason: genudp.ErrClosed})
		}
		// A SendErrorMsg -- the address not usable yet, say -- is a
		// transmission lost: the retransmission covers it.
	}
	return st, d, nil
}

// start starts the exchange of req: after its random delay, if any, or at
// once.
func (m machine) start(d data, req exchangeReq, from molecule.From) (Phase, data, []molecule.Effect) {
	r := rand.New(&d.rng)
	d.cur = exchange{
		from: from,
		x:    req.X,
		xid:  dhcpv6.NewTransactionID(r),
		rt:   dhcpv6.FirstRT(req.X.Timing.IRT, r),
	}
	if delay := dhcpv6.InitialDelay(req.X.Timing.InitialDelayMax, r); delay > 0 {
		return Delaying, d, molecule.Do(genstatem.StartStateTimeout{After: delay, Msg: transmit{}})
	}
	return m.send(d)
}

// send transmits the running exchange's message, and waits rt for an
// answer.
func (m machine) send(d data) (Phase, data, []molecule.Effect) {
	b, err := d.cur.x.Message(d.cur.xid, m.clientID, d.cur.elapsed).MarshalBinary()
	if err != nil {
		return m.finish(d, nil, err)
	}
	d.cur.sent++
	return Waiting, d, molecule.Do(
		m.sock.SendActiveEffect(m.server, b, genudp.Once),
		genstatem.StartStateTimeout{After: d.cur.rt, Msg: retransmit{}},
	)
}

// finish answers the running exchange, and takes the next.
func (m machine) finish(d data, msg *dhcpv6.Message, err error) (Phase, data, []molecule.Effect) {
	from := d.cur.from
	d.cur = exchange{}
	return Idle, d, molecule.Do(molecule.Reply{To: from, Value: exchangeRep{Msg: msg, Err: err}})
}
