package pdlease

import (
	"context"

	"github.com/shun159/miniteman/pkg/prefixdelegation"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genstatem"
	"github.com/shun159/molecule/proc"
)

// Phase is the state of the lease process: the rung of the renewal ladder
// it is on.
type Phase int

const (
	// Bound holds a lease, until its T1.
	Bound Phase = iota
	// Renewing renews the lease with its server, until its T2.
	Renewing
	// Rebinding rebinds the lease with any server, until it expires.
	Rebinding
	// Soliciting, the lease expired, acquires a new one.
	Soliciting
)

func (p Phase) String() string {
	switch p {
	case Bound:
		return "bound"
	case Renewing:
		return "renewing"
	case Rebinding:
		return "rebinding"
	case Soliciting:
		return "soliciting"
	}
	return "unknown"
}

type (
	// renewNow is the message of Bound's state timeout: T1 is here.
	renewNow struct{}
	// exchangeKey is the key of the exchange running, an Async.
	exchangeKey struct{}
)

// leaser runs the renewal ladder of a lease (RFC 3315 §18.1.3/§18.1.4,
// RFC 3633). It is pure: T1 is a state timeout, at the lease's RenewAt;
// each exchange -- which blocks, a DHCPv6 exchange retransmitting until it
// is answered or its deadline passes -- runs as an Async, its outcome
// moving the process up or down the ladder; a new lease is a cast to the
// apply process. renew, rebind and acquire are the exchanges, which tests
// replace.
//
// It traps exits, so that on shutdown Terminate releases the lease
// (RFC 3315 §18.1.6) -- through release, which blocks, bounded. A crash
// doesn't: the restarted process carries on with the binding.
type leaser struct {
	initial *prefixdelegation.Lease
	renew   func(context.Context, *prefixdelegation.Lease) (*prefixdelegation.Lease, error)
	rebind  func(context.Context, *prefixdelegation.Lease) (*prefixdelegation.Lease, error)
	acquire func(context.Context) (*prefixdelegation.Lease, error)
	release func(*prefixdelegation.Lease)
	logf    func(format string, args ...any)
}

func (l leaser) Init(proc.PID) (Phase, *prefixdelegation.Lease, []molecule.Effect, error) {
	return Bound, l.initial, molecule.Do(molecule.TrapExit{On: true}, untilT1(l.initial)), nil
}

func (l leaser) HandleEvent(ph Phase, lease *prefixdelegation.Lease, ev genstatem.Event) (Phase, *prefixdelegation.Lease, []molecule.Effect) {
	switch e := ev.(type) {
	case genstatem.StateTimeout:
		if _, ok := e.Msg.(renewNow); ok && ph == Bound {
			return Renewing, lease, molecule.Do(l.exchange(func(ctx context.Context) (*prefixdelegation.Lease, error) {
				return l.renew(ctx, lease)
			}))
		}

	case genstatem.Info:
		r, ok := e.Msg.(molecule.AsyncResult)
		if !ok || r.Key != (exchangeKey{}) {
			break
		}
		if r.Err == nil {
			return l.bound(r.Value.(*prefixdelegation.Lease))
		}
		switch ph {
		case Renewing:
			l.logf("DHCPv6-PD: Renew failed (%v): rebinding", r.Err)
			return Rebinding, lease, molecule.Do(l.exchange(func(ctx context.Context) (*prefixdelegation.Lease, error) {
				return l.rebind(ctx, lease)
			}))
		case Rebinding:
			l.logf("DHCPv6-PD: Rebind failed (%v): soliciting afresh", r.Err)
			return Soliciting, lease, molecule.Do(l.exchange(l.acquire))
		case Soliciting:
			// Acquire retries until it succeeds: an error is a panic.
			return ph, lease, molecule.Do(molecule.Stop{Reason: r.Err})
		}
	}
	return ph, lease, nil
}

// bound holds lease, newly granted: applied, renewed at its T1.
func (l leaser) bound(lease *prefixdelegation.Lease) (Phase, *prefixdelegation.Lease, []molecule.Effect) {
	return Bound, lease, molecule.Do(
		molecule.Cast{To: ApplyName, Req: applied{Lease: lease}},
		untilT1(lease),
	)
}

// exchange runs run as the exchange.
func (l leaser) exchange(run func(context.Context) (*prefixdelegation.Lease, error)) molecule.Effect {
	return molecule.Async{Key: exchangeKey{}, Run: func(ctx context.Context) (any, error) {
		lease, err := run(ctx)
		if err != nil {
			return nil, err
		}
		return lease, nil
	}}
}

func untilT1(lease *prefixdelegation.Lease) molecule.Effect {
	return genstatem.StartStateTimeout{At: lease.RenewAt(), Msg: renewNow{}}
}

// Terminate releases the lease on shutdown, while it is still valid.
func (l leaser) Terminate(ph Phase, lease *prefixdelegation.Lease, reason error) []molecule.Effect {
	if ph != Soliciting && !proc.IsAbnormal(reason) {
		l.release(lease)
	}
	return nil
}
