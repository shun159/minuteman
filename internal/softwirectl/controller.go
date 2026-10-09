package softwirectl

import (
	"log"
	"net/netip"
	"time"

	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genstatem"
	"github.com/shun159/molecule/proc"
)

// AFTR migration policy (the datapath mechanism is pkg/datapath's
// BeginMigration/Cutover/CompleteMigration; see docs/rfc-compliance-backlog.md's
// AFTR re-discovery entry for why it is shaped this way).
const (
	// primingDuration is how long the datapath records flows before the
	// cutover. It is the window in which a flow must send or receive at least
	// one packet to be recognised as pre-existing -- and that recording is the
	// only way to tell, afterwards, a pre-existing flow's next packet from a
	// brand-new flow's first one. Anything worth protecting (a call, a stream,
	// a download, a game) has sub-second gaps, so a minute is generous; a flow
	// that stays completely silent throughout is the accepted, bounded cost.
	primingDuration = 60 * time.Second

	// drainInterval is how often the drain reclaims idle flows and checks
	// whether anything is still pinned to the old AFTR.
	drainInterval = 30 * time.Second

	// maxDrainDuration caps how long the old AFTR is held open for the flows
	// still pinned to it. It is only a safety valve: the drain normally ends
	// when the last pinned flow falls idle. Keeping two AFTRs alive
	// indefinitely isn't an option, so a flow still running after this does
	// break -- which is why the cap is generous rather than tight.
	maxDrainDuration = 2 * time.Hour
)

// switchRetry is how soon re-discovery is retried after a failed migration or
// switch, and the fallback wait when a discovery reports a non-positive refresh
// interval, rather than waiting a full (day-scale) refresh: short enough to
// recover promptly, long enough not to hammer the server. (A failed *discovery*
// instead backs off per hb46pp.RetryDelay for its failure class.)
const switchRetry = 5 * time.Minute

// b4PollInterval is how often the kernel's chosen B4 source toward the AFTR is
// re-queried to notice a WAN-address change (the DS-Lite B4-address change of
// RFC 7785). Polling rather than subscribing to RTNLGRP_IPV6_IFADDR is a
// deliberate simplification (see docs/rfc-compliance-backlog.md): home-CPE
// renumbering is rare and usually rides link events slower than one poll anyway.
const b4PollInterval = 30 * time.Second

// nextRefreshWait clamps a reported refresh interval to a positive wait: a
// discovery that reports 0 (a DHCPv6 server may send information-refresh-time=0)
// falls back to switchRetry instead of busy-looping.
func nextRefreshWait(refresh time.Duration) time.Duration {
	if refresh <= 0 {
		return switchRetry
	}
	return refresh
}

// nextB4 is the decision for whether a freshly-queried B4 source is a change
// worth acting on. A query that returned no source (ok=false: the WAN route is
// momentarily gone, e.g. mid-renumbering) or an invalid/unchanged address is
// *not* a change: keep the current B4 rather than switch to something invalid,
// so a transient blip never breaks the softwire. Nor is a source that isn't
// global (see UsableB4), e.g. the link-local one the kernel falls back to while
// a renumbered WAN's new global is still DAD-tentative.
func nextB4(current, queried netip.Addr, ok bool) (b4 netip.Addr, changed bool) {
	if !ok || !UsableB4(queried) || queried == current {
		return current, false
	}
	return queried, true
}

// UsableB4 reports whether a kernel-chosen source can be the B4: the AFTR
// reaches it across the access network, so it must be a global unicast address
// (a ULA counts) -- never link-local, loopback, multicast or unspecified.
func UsableB4(addr netip.Addr) bool {
	return addr.Is6() && addr.IsGlobalUnicast()
}

// Phase is the state of the [Controller].
type Phase int

const (
	// Recovering asks the softwire which endpoints carry traffic. Every
	// start goes through it, a restart after a crash included: the softwire
	// outlives the controller, so it, not the controller's configuration, is
	// the truth.
	Recovering Phase = iota
	// Steady is on one AFTR, waiting for the next re-discovery.
	Steady
	// Discovering has a re-discovery attempt in flight.
	Discovering
	// Priming has the datapath record flows on the old AFTR before the
	// cutover to a new one.
	Priming
	// Draining has cut over: new flows go to the new AFTR, while the flows
	// recorded while priming stay on the old one until they fall idle.
	Draining
	// Switching has a hard switch of the endpoints in flight, after a
	// WAN-address change.
	Switching
)

func (p Phase) String() string {
	switch p {
	case Recovering:
		return "recovering"
	case Steady:
		return "steady"
	case Discovering:
		return "discovering"
	case Priming:
		return "priming"
	case Draining:
		return "draining"
	case Switching:
		return "switching"
	}
	return "unknown"
}

// Endpoints are the two ends of the softwire.
type Endpoints struct {
	B4, AFTR netip.Addr
}

// Discovery is one AFTR discovery outcome, carrying what re-discovery needs to
// pace itself.
type Discovery struct {
	AFTR       netip.Addr
	DNSServers []netip.Addr  // RFC 3646 servers from the DHCPv6 Reply; nil for a static -aftr
	Refresh    time.Duration // RFC 4242 / HB46PP ttl; 0 for a static -aftr
	// HB46PPToken is the token an HB46PP provisioning response asked us to
	// echo on the next request (v6mig-1 §3.3).
	HB46PPToken string
}

// Counts are the datapath's flow-affinity counters, cumulative across the
// process.
type Counts struct {
	AffinityInsert, AffinityInsertFail uint64
}

// Data is the data of the [Controller].
type Data struct {
	Current Discovery  // the AFTR in use, with its refresh pacing and token
	B4      netip.Addr // the B4 in use
	Wait    time.Duration

	// Gen is bumped by a hard switch, which ends whatever was in flight: a
	// response tagged with an earlier generation is stale and dropped.
	Gen uint64

	// The migration in progress, in Priming and Draining.
	Next       Discovery // the AFTR being moved to
	Migration  uint64    // counts migrations, so a drain cap of an earlier one is ignored
	Baseline   Counts    // the counters when priming began
	Recorded   uint64    // flows recorded while priming, for the log
	CapReached bool      // the drain has run for maxDrainDuration
	AbortWhy   string    // why the migration is being rolled back; "" if already logged

	// The hard switch in progress, in Switching.
	SwitchB4 netip.Addr
	SwitchTo Discovery
}

// Controller is the sole owner of the live softwire endpoints. It re-discovers
// the AFTR (RFC 4242 periodic re-discovery, applying a changed AFTR through
// the flow-preserving migration) when the AFTR is dynamic, and follows the WAN
// source (hard-switching the softwire on a change, the DS-Lite B4-address
// change of RFC 7785) when the B4 is.
//
// It is pure: the datapath, the tunnel and the netlink socket are driven by the
// softwire server ([SoftwireName]), discovery runs in the discovery process
// ([DiscoveryName]), and the controller only sends them requests and handles
// their responses.
type Controller struct {
	DynamicAFTR bool
	DynamicB4   bool
	// Initial is what startup discovered, or the static -aftr.
	Initial Discovery
	// Logf logs; log.Printf if nil.
	Logf func(format string, args ...any)
}

// Messages of the controller's timeouts.
type (
	refresh   struct{} // Steady: re-discover
	primed    struct{} // Priming: the priming window is over
	drainTick struct{} // Draining: reclaim idle flows
	b4Poll    struct{} // any phase: re-query the WAN source
	drainCap  struct{ Migration uint64 }
)

// Names of the generic timeouts.
const (
	b4PollTimer   = "b4-poll"
	drainCapTimer = "drain-cap"
)

// op names a request in flight, in the tag of its response.
type op int

const (
	opRecover op = iota
	opSource
	opSwitch
	opDiscover
	opBegin
	opCounts
	opAbort
	opCutover
	opGC
	opComplete
)

type tag struct {
	Op  op
	Gen uint64
}

func (c Controller) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (Controller) StateEnter() bool { return true }

func (Controller) Init(proc.PID) (Phase, Data, []molecule.Effect, error) {
	return Recovering, Data{}, molecule.Do(softwire(opRecover, 0, recoverReq{})), nil
}

func (c Controller) HandleEvent(st Phase, d Data, ev genstatem.Event) (Phase, Data, []molecule.Effect) {
	switch e := ev.(type) {
	case genstatem.Enter[Phase]:
		return c.enter(st, d)

	case genstatem.StateTimeout:
		switch e.Msg.(type) {
		case refresh:
			return Discovering, d, molecule.Do(molecule.SendRequest{
				To: DiscoveryName, Req: discoverReq{Token: d.Current.HB46PPToken}, Tag: tag{opDiscover, d.Gen},
			})
		case primed:
			return st, d, molecule.Do(softwire(opCounts, d.Gen, countsReq{}))
		case drainTick:
			return st, d, molecule.Do(softwire(opGC, d.Gen, gcReq{}))
		}

	case genstatem.Timeout:
		switch m := e.Msg.(type) {
		case b4Poll:
			if st == Switching {
				// Compared against a B4 not yet applied, the source would
				// look like a change again.
				return st, d, molecule.Do(genstatem.Postpone{})
			}
			return st, d, molecule.Do(
				softwire(opSource, d.Gen, sourceReq{AFTR: d.Current.AFTR}),
				genstatem.StartTimeout{Name: b4PollTimer, After: b4PollInterval, Msg: b4Poll{}},
			)
		case drainCap:
			if m.Migration == d.Migration {
				d.CapReached = true
			}
			return st, d, nil
		}

	case genstatem.Info:
		r, ok := e.Msg.(molecule.Response)
		if !ok {
			break
		}
		t, ok := r.Tag.(tag)
		if !ok || t.Gen != d.Gen {
			return st, d, nil
		}
		return c.response(st, d, t.Op, r)
	}
	return st, d, nil
}

func (c Controller) enter(st Phase, d Data) (Phase, Data, []molecule.Effect) {
	switch st {
	case Steady:
		if c.DynamicAFTR {
			return st, d, molecule.Do(genstatem.StartStateTimeout{After: d.Wait, Msg: refresh{}})
		}
	case Draining:
		d.CapReached = false
		return st, d, molecule.Do(
			genstatem.StartStateTimeout{After: drainInterval, Msg: drainTick{}},
			genstatem.StartTimeout{Name: drainCapTimer, After: maxDrainDuration, Msg: drainCap{d.Migration}},
		)
	}
	return st, d, nil
}

func (c Controller) response(st Phase, d Data, o op, r molecule.Response) (Phase, Data, []molecule.Effect) {
	switch o {
	case opRecover:
		rep, err := reply[recovered](r)
		if err == nil {
			err = rep.Err
		}
		if err != nil {
			// Without knowing the endpoints there is nothing safe to do; the
			// supervisor tries again.
			return st, d, molecule.Do(molecule.Stop{Reason: err})
		}
		return c.recovered(d, rep.Endpoints)

	case opSource:
		rep, err := reply[sourceRep](r)
		if err == nil {
			err = rep.Err
		}
		if err != nil {
			c.logf("dynamic B4: querying the WAN source failed: %v (will retry)", err)
			return st, d, nil
		}
		b4, changed := nextB4(d.B4, rep.Addr, rep.OK)
		if !changed {
			return st, d, nil
		}
		return c.hardSwitch(st, d, b4)

	case opSwitch:
		if err := done(r); err != nil {
			c.logf("dynamic B4: switching softwire source to %s failed: %v (keeping %s)", d.SwitchB4, err, d.B4)
			d.Wait = switchRetry
			return Steady, d, nil
		}
		c.logf("dynamic B4: switched softwire source to %s toward AFTR %s; re-triggering AFTR discovery", d.SwitchB4, d.SwitchTo.AFTR)
		d.B4, d.Current = d.SwitchB4, d.SwitchTo
		d.Wait = 0
		return Steady, d, nil

	case opDiscover:
		rep, err := reply[discoverRep](r)
		if err == nil {
			err = rep.Err
		}
		if err != nil {
			d.Current.Refresh = rep.RetryIn
			d.Wait = nextRefreshWait(rep.RetryIn)
			c.logf("AFTR re-discovery failed: %v (keeping %s, retrying in %v)", err, d.Current.AFTR, d.Wait.Round(time.Second))
			return Steady, d, nil
		}
		next := rep.Disc
		if next.AFTR == d.Current.AFTR {
			c.logf("AFTR re-discovery: unchanged (%s), next refresh in %v", d.Current.AFTR, nextRefreshWait(next.Refresh).Round(time.Second))
			d.Current = next
			d.Wait = nextRefreshWait(next.Refresh)
			return Steady, d, nil
		}
		d.Next = next
		d.Migration++
		return Priming, d, molecule.Do(softwire(opBegin, d.Gen, beginReq{To: Endpoints{d.B4, next.AFTR}}))

	case opBegin:
		counts, err := reply[countsRep](r)
		if err == nil {
			err = counts.Err
		}
		if err != nil {
			return c.migrationFailed(d, err.Error())
		}
		d.Baseline = counts.Counts
		c.logf("AFTR migration: priming %v on %s before moving to %s", primingDuration, d.Current.AFTR, d.Next.AFTR)
		return st, d, molecule.Do(genstatem.StartStateTimeout{After: primingDuration, Msg: primed{}})

	case opCounts:
		counts, err := reply[countsRep](r)
		if err == nil {
			err = counts.Err
		}
		if err != nil {
			return c.abort(d, "reading datapath stats: "+err.Error())
		}
		// A flow the datapath couldn't record may well be one that predates
		// the switch, and cutting over would move it to an AFTR holding no
		// NAT state for it. Staying on an AFTR that still works is the safe
		// answer.
		if lost := counts.AffinityInsertFail - d.Baseline.AffinityInsertFail; lost > 0 {
			c.logf("AFTR migration: abandoning -- the flow-affinity table filled up, so %d flow(s) went "+
				"unrecorded and would break at the cutover; staying on %s", lost, d.Current.AFTR)
			return c.abort(d, "")
		}
		d.Recorded = counts.AffinityInsert - d.Baseline.AffinityInsert
		return st, d, molecule.Do(softwire(opCutover, d.Gen, cutoverReq{}))

	case opCutover:
		if err := done(r); err != nil {
			return c.abort(d, err.Error())
		}
		c.logf("AFTR migration: cut over to %s; the %d flow(s) recorded on %s stay there until they fall idle",
			d.Next.AFTR, d.Recorded, d.Current.AFTR)
		return Draining, d, nil

	case opAbort:
		if err := done(r); err != nil {
			// The datapath is stuck in PRIMING, which blocks every later
			// migration: not a benign abandonment.
			return c.migrationFailed(d, "rolling the migration back after "+d.AbortWhy+" failed, leaving the datapath mid-migration: "+err.Error())
		}
		if d.AbortWhy == "" {
			d.Wait = switchRetry
			return Steady, d, nil
		}
		return c.migrationFailed(d, d.AbortWhy)

	case opGC:
		rep, err := reply[gcRep](r)
		if err == nil {
			err = rep.Err
		}
		switch {
		case err != nil:
			c.logf("AFTR migration: draining %s: %v (retrying)", d.Current.AFTR, err)
		case rep.Remaining > 0 && !d.CapReached:
		default:
			if rep.Remaining > 0 {
				c.logf("AFTR migration: drain cap of %v reached with %d flow(s) still on %s; retiring it anyway",
					maxDrainDuration, rep.Remaining, d.Current.AFTR)
			}
			return st, d, molecule.Do(softwire(opComplete, d.Gen, completeReq{}))
		}
		return st, d, molecule.Do(genstatem.StartStateTimeout{After: drainInterval, Msg: drainTick{}})

	case opComplete:
		if err := done(r); err != nil {
			// Retried rather than given up: leaving the datapath mid-drain
			// would block every later migration.
			c.logf("AFTR migration: retiring %s: %v (retrying)", d.Current.AFTR, err)
			return st, d, molecule.Do(genstatem.StartStateTimeout{After: drainInterval, Msg: drainTick{}})
		}
		c.logf("AFTR migration: complete, %s retired", d.Current.AFTR)
		c.logf("AFTR re-discovery: now on %s (next refresh in %v)", d.Next.AFTR, nextRefreshWait(d.Next.Refresh).Round(time.Second))
		d.Current, d.Next = d.Next, Discovery{}
		d.Wait = nextRefreshWait(d.Current.Refresh)
		return Steady, d, molecule.Do(genstatem.CancelTimeout{Name: drainCapTimer})
	}
	return st, d, nil
}

// recovered starts the controller on the endpoints the softwire carries.
func (c Controller) recovered(d Data, ep Endpoints) (Phase, Data, []molecule.Effect) {
	d.B4 = ep.B4
	if ep.AFTR == c.Initial.AFTR {
		d.Current = c.Initial
		d.Wait = nextRefreshWait(c.Initial.Refresh)
	} else {
		// Moved since startup, by a controller that crashed and took its
		// refresh pacing and token with it: re-discover now.
		d.Current = Discovery{AFTR: ep.AFTR}
		d.Wait = 0
	}
	var effs []molecule.Effect
	if c.DynamicB4 {
		effs = append(effs, genstatem.StartTimeout{Name: b4PollTimer, After: b4PollInterval, Msg: b4Poll{}})
	}
	return Steady, d, effs
}

// hardSwitch moves the softwire onto a new B4 at once. A B4 change can't be
// drained -- the AFTR's NAT state dies with the address -- so whatever was in
// flight is dropped: a migration ends (SwitchAFTR ends one in any phase), and a
// discovery is cancelled, to run again once the switch has landed, as the VNE
// may map the new prefix to a different AFTR.
func (c Controller) hardSwitch(st Phase, d Data, b4 netip.Addr) (Phase, Data, []molecule.Effect) {
	var effs []molecule.Effect
	to := d.Current
	switch st {
	case Discovering:
		effs = append(effs, molecule.Cast{To: DiscoveryName, Req: cancelDiscovery{}})
	case Draining:
		// New flows are on the new AFTR already: stay there.
		to = d.Next
	}
	c.logf("dynamic B4: WAN source now %s, differs from the applied B4 %s -- switching", b4, d.B4)
	d.Gen++
	d.SwitchB4, d.SwitchTo = b4, to
	d.Next = Discovery{}
	effs = append(effs, softwire(opSwitch, d.Gen, switchReq{To: Endpoints{b4, to.AFTR}}))
	return Switching, d, effs
}

// abort rolls a primed migration back to the AFTR still carrying traffic.
// why is logged once the rollback is done, unless empty.
func (c Controller) abort(d Data, why string) (Phase, Data, []molecule.Effect) {
	d.AbortWhy = why
	return Priming, d, molecule.Do(softwire(opAbort, d.Gen, abortReq{}))
}

// migrationFailed stays on the AFTR still carrying traffic, and tries the
// whole move again later.
func (c Controller) migrationFailed(d Data, why string) (Phase, Data, []molecule.Effect) {
	c.logf("AFTR migration to %s failed: %s (staying on %s)", d.Next.AFTR, why, d.Current.AFTR)
	d.Next = Discovery{}
	d.Wait = switchRetry
	return Steady, d, nil
}

func softwire(o op, gen uint64, req request) molecule.Effect {
	return molecule.SendRequest{To: SoftwireName, Req: req, Tag: tag{o, gen}}
}

// reply returns the value of a response, or the error of a request that got
// none, the server having died.
func reply[T any](r molecule.Response) (T, error) {
	v, _ := r.Value.(T)
	return v, r.Err
}

// done returns the error of a request answered with a doneRep.
func done(r molecule.Response) error {
	rep, err := reply[doneRep](r)
	if err != nil {
		return err
	}
	return rep.Err
}
