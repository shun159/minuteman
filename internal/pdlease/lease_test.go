package pdlease

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/shun159/miniteman/pkg/prefixdelegation"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genstatem"
	"github.com/shun159/molecule/proc"
)

var t0 = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)

func lease(prefix string, at time.Time) *prefixdelegation.Lease {
	return &prefixdelegation.Lease{
		Prefixes: []prefixdelegation.IAPrefix{{
			PreferredLifetime: time.Hour, ValidLifetime: 2 * time.Hour,
			Prefix: netip.MustParsePrefix(prefix),
		}},
		T1: 30 * time.Minute, T2: 48 * time.Minute,
		AcquiredAt: at,
	}
}

// rig is a leaser whose exchanges record which ran, answering with the
// lease or error set.
type rig struct {
	l        leaser
	ran      []string
	answer   *prefixdelegation.Lease
	fail     error
	released []*prefixdelegation.Lease
}

func newRig(t *testing.T, initial *prefixdelegation.Lease) *rig {
	r := &rig{}
	answer := func(name string) (*prefixdelegation.Lease, error) {
		r.ran = append(r.ran, name)
		return r.answer, r.fail
	}
	r.l = leaser{
		initial: initial,
		renew: func(_ context.Context, l *prefixdelegation.Lease) (*prefixdelegation.Lease, error) {
			return answer("renew " + l.Prefixes[0].Prefix.String())
		},
		rebind: func(_ context.Context, l *prefixdelegation.Lease) (*prefixdelegation.Lease, error) {
			return answer("rebind " + l.Prefixes[0].Prefix.String())
		},
		acquire: func(context.Context) (*prefixdelegation.Lease, error) { return answer("acquire") },
		release: func(l *prefixdelegation.Lease) { r.released = append(r.released, l) },
		logf:    t.Logf,
	}
	return r
}

// run runs the exchange among effs, as molecule would, and returns its
// outcome as the process gets it.
func (r *rig) run(t *testing.T, effs []molecule.Effect) genstatem.Event {
	t.Helper()
	for _, e := range effs {
		if a, ok := e.(molecule.Async); ok {
			v, err := a.Run(context.Background())
			return genstatem.Info{Msg: molecule.AsyncResult{Key: a.Key, Value: v, Err: err}}
		}
	}
	t.Fatalf("no exchange among %v", effs)
	return nil
}

func renewsAt(effs []molecule.Effect) time.Time {
	for _, e := range effs {
		if s, ok := e.(genstatem.StartStateTimeout); ok && s.Msg == (renewNow{}) {
			return s.At
		}
	}
	return time.Time{}
}

func applies(effs []molecule.Effect) []*prefixdelegation.Lease {
	var ls []*prefixdelegation.Lease
	for _, e := range effs {
		if c, ok := e.(molecule.Cast); ok && c.To == ApplyName {
			ls = append(ls, c.Req.(applied).Lease)
		}
	}
	return ls
}

// The lease is renewed at T1, and the renewed lease applied and renewed at
// its own T1.
func TestRenew(t *testing.T) {
	initial := lease("2001:db8:1::/56", t0)
	r := newRig(t, initial)
	ph, d, effs, err := r.l.Init(proc.PID{})
	if err != nil || ph != Bound || d != initial {
		t.Fatalf("Init: %v %v %v", ph, d, err)
	}
	if at := renewsAt(effs); !at.Equal(t0.Add(30 * time.Minute)) {
		t.Errorf("renews at %v, want T1", at)
	}
	if len(applies(effs)) != 0 {
		t.Error("the initial lease applied again: the caller has")
	}

	ph, d, effs = r.l.HandleEvent(ph, d, genstatem.StateTimeout{Msg: renewNow{}})
	if ph != Renewing {
		t.Fatalf("at T1: %v", ph)
	}
	renewed := lease("2001:db8:1::/56", t0.Add(30*time.Minute))
	r.answer = renewed
	ph, d, effs = r.l.HandleEvent(ph, d, r.run(t, effs))
	if ph != Bound || d != renewed {
		t.Fatalf("renewed: %v %v", ph, d)
	}
	if a := applies(effs); len(a) != 1 || a[0] != renewed {
		t.Errorf("applied %v, want the renewed lease", a)
	}
	if at := renewsAt(effs); !at.Equal(renewed.RenewAt()) {
		t.Errorf("renews at %v, want the renewed lease's T1", at)
	}
	if want := []string{"renew 2001:db8:1::/56"}; len(r.ran) != 1 || r.ran[0] != want[0] {
		t.Errorf("ran %v, want %v", r.ran, want)
	}
}

// A failed Renew falls back to Rebind, a failed Rebind to soliciting
// afresh, whose lease is bound.
func TestLadder(t *testing.T) {
	r := newRig(t, lease("2001:db8:1::/56", t0))
	ph, d, _, _ := r.l.Init(proc.PID{})
	ph, d, effs := r.l.HandleEvent(ph, d, genstatem.StateTimeout{Msg: renewNow{}})

	r.fail = context.DeadlineExceeded
	ph, d, effs = r.l.HandleEvent(ph, d, r.run(t, effs))
	if ph != Rebinding {
		t.Fatalf("after a failed Renew: %v", ph)
	}
	ph, d, effs = r.l.HandleEvent(ph, d, r.run(t, effs))
	if ph != Soliciting {
		t.Fatalf("after a failed Rebind: %v", ph)
	}

	fresh := lease("2001:db8:2::/56", t0.Add(3*time.Hour))
	r.answer, r.fail = fresh, nil
	ph, d, effs = r.l.HandleEvent(ph, d, r.run(t, effs))
	if ph != Bound || d != fresh {
		t.Fatalf("acquired: %v %v", ph, d)
	}
	if a := applies(effs); len(a) != 1 || a[0] != fresh {
		t.Errorf("applied %v, want the fresh lease", a)
	}
	want := []string{"renew 2001:db8:1::/56", "rebind 2001:db8:1::/56", "acquire"}
	if len(r.ran) != len(want) {
		t.Fatalf("ran %v, want %v", r.ran, want)
	}
	for i := range want {
		if r.ran[i] != want[i] {
			t.Errorf("ran %v, want %v", r.ran, want)
		}
	}
}

// A rebound lease is bound like a renewed one.
func TestRebound(t *testing.T) {
	r := newRig(t, lease("2001:db8:1::/56", t0))
	ph, d, _, _ := r.l.Init(proc.PID{})
	ph, d, effs := r.l.HandleEvent(ph, d, genstatem.StateTimeout{Msg: renewNow{}})
	r.fail = context.DeadlineExceeded
	ph, d, effs = r.l.HandleEvent(ph, d, r.run(t, effs))
	rebound := lease("2001:db8:1::/56", t0.Add(50*time.Minute))
	r.answer, r.fail = rebound, nil
	ph, d, effs = r.l.HandleEvent(ph, d, r.run(t, effs))
	if ph != Bound || d != rebound || len(applies(effs)) != 1 {
		t.Errorf("rebound: %v %v %v", ph, d, effs)
	}
}

// Soliciting retries until it succeeds: an error is a crash.
func TestSolicitCrash(t *testing.T) {
	r := newRig(t, lease("2001:db8:1::/56", t0))
	boom := errors.New("boom")
	_, _, effs := r.l.HandleEvent(Soliciting, r.l.initial, genstatem.Info{Msg: molecule.AsyncResult{Key: exchangeKey{}, Err: boom}})
	if len(effs) != 1 || effs[0] != (molecule.Stop{Reason: boom}) {
		t.Errorf("%v, want a stop", effs)
	}
}

// The lease is released on shutdown while valid, not on a crash -- the
// restarted process carries on with it -- and not once it has expired.
func TestRelease(t *testing.T) {
	for _, tc := range []struct {
		ph      Phase
		reason  error
		release bool
	}{
		{Bound, proc.Shutdown, true},
		{Renewing, proc.Shutdown, true},
		{Rebinding, proc.Normal, true},
		{Soliciting, proc.Shutdown, false},
		{Bound, errors.New("crash"), false},
	} {
		r := newRig(t, lease("2001:db8:1::/56", t0))
		r.l.Terminate(tc.ph, r.l.initial, tc.reason)
		if got := len(r.released) == 1; got != tc.release {
			t.Errorf("%v, %v: released %v, want %v", tc.ph, tc.reason, got, tc.release)
		}
	}
}
