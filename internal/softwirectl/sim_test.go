package softwirectl

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/shun159/miniteman/pkg/datapath"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genstatem"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/gensim"
)

var (
	b4A   = netip.MustParseAddr("2001:db8:a::1")
	b4B   = netip.MustParseAddr("2001:db8:b::1")
	aftr1 = netip.MustParseAddr("2001:db8:ff::1")
	aftr2 = netip.MustParseAddr("2001:db8:ff::2")
)

const day = 24 * time.Hour

// fakeDP models the datapath's migration states, and logs what it is asked.
type fakeDP struct {
	calls     []string
	state     string // steady, priming, draining
	stats     datapath.Stats
	lostFlows uint64 // flows BeginMigration's priming fails to record
	remaining []int  // what successive GCFlowAffinity calls report
}

func (f *fakeDP) call(format string, args ...any) {
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
}

func (f *fakeDP) Stats() (datapath.Stats, error) { return f.stats, nil }

func (f *fakeDP) SwitchAFTR(b4, aftr netip.Addr) error {
	f.call("switch %s %s", b4, aftr)
	f.state = "steady"
	return nil
}

func (f *fakeDP) BeginMigration(b4, aftr netip.Addr) error {
	f.call("begin %s %s", b4, aftr)
	if f.state != "steady" {
		return errors.New("migration already in progress")
	}
	f.state = "priming"
	f.stats.AffinityInsert += 3
	f.stats.AffinityInsertFail += f.lostFlows
	return nil
}

func (f *fakeDP) Cutover() error {
	f.call("cutover")
	f.state = "draining"
	return nil
}

func (f *fakeDP) AbortMigration() error {
	f.call("abort")
	f.state = "steady"
	return nil
}

func (f *fakeDP) GCFlowAffinity(datapath.FlowIdleTimeouts) (int, error) {
	f.call("gc")
	if len(f.remaining) == 0 {
		return 0, nil
	}
	n := f.remaining[0]
	f.remaining = f.remaining[1:]
	return n, nil
}

func (f *fakeDP) CompleteMigration() error {
	f.call("complete")
	f.state = "steady"
	return nil
}

type fakeTunnel struct{ ep Endpoints }

func (f *fakeTunnel) SetEndpoints(b4, aftr netip.Addr) error {
	f.ep = Endpoints{b4, aftr}
	return nil
}

type fakeRouter struct{ src netip.Addr }

func (f *fakeRouter) SourceForDest(int, netip.Addr) (netip.Addr, bool, error) {
	return f.src, f.src.IsValid(), nil
}

// attempt is a discovery attempt's scripted outcome.
type attempt struct {
	disc Discovery
	err  error
}

// rig is a softwire control tree under simulation.
type rig struct {
	t      *testing.T
	sim    *gensim.Sim
	dp     *fakeDP
	tun    *fakeTunnel
	router *fakeRouter
	script []attempt
}

func newRig(t *testing.T, script ...attempt) *rig {
	r := &rig{
		t:      t,
		sim:    gensim.New(1),
		dp:     &fakeDP{state: "steady"},
		tun:    &fakeTunnel{},
		router: &fakeRouter{src: b4A},
		script: script,
	}
	start := Endpoints{b4A, aftr1}
	cfg := Config{
		Softwire: NewSoftwire(r.dp, r.tun, r.router, 1, start),
		Controller: Controller{
			DynamicAFTR: true,
			DynamicB4:   true,
			Initial:     Discovery{AFTR: aftr1, Refresh: day},
			Discover:    r.discover,
			RetryDelay:  func(error) time.Duration { return time.Hour },
			Logf:        t.Logf,
		},
	}
	if _, err := gensim.Start(r.sim, supervisor.Child(Spec(cfg))); err != nil {
		t.Fatal(err)
	}
	r.sim.RunUntilIdle()
	return r
}

// discover answers discovery attempts with the script, the last outcome
// again when it runs out. In gensim, the Async running it runs at once.
func (r *rig) discover(context.Context, string) (Discovery, error) {
	a := r.script[0]
	if len(r.script) > 1 {
		r.script = r.script[1:]
	}
	return a.disc, a.err
}

func (r *rig) controller() (Phase, Data) {
	r.t.Helper()
	pid, ok := r.sim.WhereIs(string(ControllerName))
	if !ok {
		r.t.Fatal("no controller")
	}
	m, ok := gensim.State[genstatem.Machine[Phase, Data]](r.sim, pid)
	if !ok {
		r.t.Fatal("no controller state")
	}
	return m.State(), m.Data()
}

func (r *rig) wantPhase(want Phase) Data {
	r.t.Helper()
	st, d := r.controller()
	if st != want {
		r.t.Fatalf("controller %v, want %v\ndatapath calls: %q", st, want, r.dp.calls)
	}
	return d
}

func (r *rig) wantCalls(want ...string) {
	r.t.Helper()
	if !slices.Equal(r.dp.calls, want) {
		r.t.Fatalf("datapath calls:\n%q\nwant:\n%q", r.dp.calls, want)
	}
	r.dp.calls = nil
}

func TestMigration(t *testing.T) {
	r := newRig(t, attempt{disc: Discovery{AFTR: aftr2, Refresh: day}})
	r.dp.remaining = []int{2}
	r.wantPhase(Steady)

	r.sim.Advance(day)
	d := r.wantPhase(Priming)
	if d.Next.AFTR != aftr2 {
		t.Fatalf("moving to %v, want %v", d.Next.AFTR, aftr2)
	}
	r.wantCalls("begin 2001:db8:a::1 2001:db8:ff::2")

	r.sim.Advance(primingDuration)
	r.wantPhase(Draining)
	r.wantCalls("cutover")
	if r.tun.ep != (Endpoints{b4A, aftr2}) {
		t.Errorf("tunnel on %v after the cutover", r.tun.ep)
	}

	r.sim.Advance(drainInterval) // two flows left
	r.wantPhase(Draining)
	r.sim.Advance(drainInterval)
	d = r.wantPhase(Steady)
	r.wantCalls("gc", "gc", "complete")
	if d.Current.AFTR != aftr2 {
		t.Errorf("on %v after the migration, want %v", d.Current.AFTR, aftr2)
	}
}

func TestMigrationAbandonedOnLostFlows(t *testing.T) {
	r := newRig(t, attempt{disc: Discovery{AFTR: aftr2, Refresh: day}})
	r.dp.lostFlows = 1

	r.sim.Advance(day + primingDuration)
	d := r.wantPhase(Steady)
	r.wantCalls("begin 2001:db8:a::1 2001:db8:ff::2", "abort")
	if d.Current.AFTR != aftr1 || d.Wait != switchRetry {
		t.Errorf("on %v retrying in %v, want %v in %v", d.Current.AFTR, d.Wait, aftr1, switchRetry)
	}
}

// A WAN-address change mid-drain switches onto the new AFTR, where new flows
// already go, and re-discovers at once.
func TestWANChangeWhileDraining(t *testing.T) {
	r := newRig(t,
		attempt{disc: Discovery{AFTR: aftr2, Refresh: day}},
		attempt{disc: Discovery{AFTR: aftr2, Refresh: day}},
	)
	r.dp.remaining = []int{5, 5, 5, 5}
	r.sim.Advance(day + primingDuration)
	r.wantPhase(Draining)
	r.dp.calls = nil

	r.router.src = b4B
	r.sim.Advance(b4PollInterval)
	d := r.wantPhase(Steady)
	if d.B4 != b4B || d.Current.AFTR != aftr2 {
		t.Fatalf("on %v -> %v, want %v -> %v", d.B4, d.Current.AFTR, b4B, aftr2)
	}
	if !slices.Contains(r.dp.calls, "switch 2001:db8:b::1 2001:db8:ff::2") {
		t.Fatalf("no switch onto the new B4 and AFTR: %q", r.dp.calls)
	}
	if r.dp.state != "steady" {
		t.Errorf("datapath left %s", r.dp.state)
	}
}

// A WAN-address change while discovering cancels the attempt, whose outcome
// then never arrives, and switches; the switch landing re-discovers at once.
// Called directly: in gensim the attempt is done before anything can come in
// between.
func TestWANChangeWhileDiscovering(t *testing.T) {
	c := Controller{DynamicAFTR: true, DynamicB4: true, Logf: t.Logf}
	d := Data{B4: b4A, Current: Discovery{AFTR: aftr1, Refresh: day}}
	st, d, effs := c.HandleEvent(Discovering, d, genstatem.Info{Msg: molecule.Response{
		Tag: tag{opSource, d.Gen}, Value: sourceRep{Addr: b4B, OK: true},
	}})
	if st != Switching {
		t.Fatalf("on a WAN change while discovering: %v", st)
	}
	cancelled := false
	for _, e := range effs {
		if ca, ok := e.(molecule.CancelAsync); ok && ca.Key == (discoverKey{}) {
			cancelled = true
		}
	}
	if !cancelled {
		t.Errorf("the discovery attempt was not cancelled: %v", effs)
	}
	st, d, _ = c.HandleEvent(st, d, genstatem.Info{Msg: molecule.Response{
		Tag: tag{opSwitch, d.Gen}, Value: doneRep{},
	}})
	if st != Steady || d.B4 != b4B || d.Current.AFTR != aftr1 || d.Wait != 0 {
		t.Errorf("after the switch: %v on %v -> %v, re-discovery in %v", st, d.B4, d.Current.AFTR, d.Wait)
	}
}

// A controller dying mid-drain is restarted by its supervisor, and recovers
// from the softwire: the migration is ended where new flows go, and the AFTR,
// moved since startup, re-discovered at once.
func TestControllerCrashWhileDraining(t *testing.T) {
	r := newRig(t, attempt{disc: Discovery{AFTR: aftr2, Refresh: day}})
	r.dp.remaining = []int{5, 5, 5, 5}
	r.sim.Advance(day + primingDuration)
	r.wantPhase(Draining)
	r.dp.calls = nil

	pid, _ := r.sim.WhereIs(string(ControllerName))
	r.sim.Exit(pid, errors.New("boom"))
	r.sim.RunUntilIdle()

	d := r.wantPhase(Steady)
	if d.Current.AFTR != aftr2 {
		t.Fatalf("recovered on %v, want %v", d.Current.AFTR, aftr2)
	}
	if d.Wait != 0 {
		t.Errorf("re-discovery in %v, want at once", d.Wait)
	}
	r.wantCalls("switch 2001:db8:a::1 2001:db8:ff::2")
}

// Stale responses, of a generation a hard switch ended, are dropped.
func TestStaleResponseDropped(t *testing.T) {
	c := Controller{DynamicAFTR: true, Logf: t.Logf}
	d := Data{Gen: 2, Current: Discovery{AFTR: aftr1}}
	st, d2, effs := c.HandleEvent(Steady, d, genstatem.Info{Msg: molecule.Response{
		Tag: tag{opDiscover, 1}, Value: discoverRep{Disc: Discovery{AFTR: aftr2}},
	}})
	if st != Steady || d2.Current.AFTR != aftr1 || effs != nil {
		t.Errorf("stale response acted on: %v %v %v", st, d2.Current.AFTR, effs)
	}
}
