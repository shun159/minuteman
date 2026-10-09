package softwirectl

import (
	"errors"
	"log"
	"net/netip"
	"time"

	"github.com/shun159/miniteman/pkg/datapath"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
)

// flowIdle bounds how long a pinned flow may go silent -- in *either*
// direction, since the datapath refreshes from both -- before the drain stops
// holding the old AFTR for it. An active flow refreshes continuously, so these
// only need to exceed a normal gap in its traffic; and once the AFTR's own NAT
// entry has timed out, the pin is worthless anyway.
var flowIdle = datapath.FlowIdleTimeouts{
	TCP:   30 * time.Minute,
	Other: 5 * time.Minute,
}

// Datapath is what the softwire drives of a *datapath.Loader.
type Datapath interface {
	Stats() (datapath.Stats, error)
	SwitchAFTR(b4, aftr netip.Addr) error
	BeginMigration(b4, aftr netip.Addr) error
	Cutover() error
	AbortMigration() error
	GCFlowAffinity(datapath.FlowIdleTimeouts) (remaining int, err error)
	CompleteMigration() error
}

// Tunnel is the companion ip6tnl slow path, a *slowpath.Tunnel.
type Tunnel interface {
	SetEndpoints(b4, aftr netip.Addr) error
}

// Router answers the kernel's source selection, a *netlink.Socket.
type Router interface {
	SourceForDest(ifindex int, dst netip.Addr) (src netip.Addr, ok bool, err error)
}

// Softwire is the live softwire: the datapath, its companion tunnel, and the
// endpoints they carry. It outlives the process serving it, so that a
// restarted controller learns from it where traffic goes.
type Softwire struct {
	dp         Datapath
	tun        Tunnel
	nl         Router // nil for a static B4
	wanIfindex int

	active    Endpoints // where new flows go
	target    Endpoints // during a migration, where it moves to
	migrating bool
}

// NewSoftwire returns the softwire carried by dp and tun on active. nl, nil
// for a static B4, selects the B4 source out of the WAN interface wanIfindex.
func NewSoftwire(dp Datapath, tun Tunnel, nl Router, wanIfindex int, active Endpoints) *Softwire {
	return &Softwire{dp: dp, tun: tun, nl: nl, wanIfindex: wanIfindex, active: active}
}

// Requests to the softwire, and their replies.
type (
	request interface{ request() }

	recoverReq  struct{}
	sourceReq   struct{ AFTR netip.Addr }
	switchReq   struct{ To Endpoints }
	beginReq    struct{ To Endpoints }
	countsReq   struct{}
	abortReq    struct{}
	cutoverReq  struct{}
	gcReq       struct{}
	completeReq struct{}

	recovered struct {
		Endpoints Endpoints
		Err       error
	}
	sourceRep struct {
		Addr netip.Addr
		OK   bool
		Err  error
	}
	countsRep struct {
		Counts
		Err error
	}
	gcRep struct {
		Remaining int
		Err       error
	}
	doneRep struct{ Err error }
)

func (recoverReq) request()  {}
func (sourceReq) request()   {}
func (switchReq) request()   {}
func (beginReq) request()    {}
func (countsReq) request()   {}
func (abortReq) request()    {}
func (cutoverReq) request()  {}
func (gcReq) request()       {}
func (completeReq) request() {}

// server serves the softwire to the controller. It is where the controller's
// decisions meet the kernel, and so not pure: each request is a few map
// updates or a netlink round trip, done as it is handled.
type server struct {
	genserver.Default[struct{}]
	sw *Softwire
}

func (s server) HandleCall(st struct{}, req request, from genserver.From[any]) (struct{}, []molecule.Effect) {
	return st, molecule.Do(from.Reply(s.sw.handle(req)))
}

func (sw *Softwire) handle(req request) any {
	switch r := req.(type) {
	case recoverReq:
		// A migration whose controller died is ended where traffic goes:
		// nothing is left to finish it.
		if sw.migrating {
			if err := sw.dp.SwitchAFTR(sw.active.B4, sw.active.AFTR); err != nil {
				return recovered{Err: err}
			}
			sw.migrating = false
			sw.setTunnel(sw.active)
		}
		return recovered{Endpoints: sw.active}

	case sourceReq:
		if sw.nl == nil {
			return sourceRep{Err: errors.New("no netlink socket to select the B4 source with")}
		}
		src, ok, err := sw.nl.SourceForDest(sw.wanIfindex, r.AFTR)
		return sourceRep{src, ok, err}

	case switchReq:
		if err := sw.dp.SwitchAFTR(r.To.B4, r.To.AFTR); err != nil {
			return doneRep{err}
		}
		sw.active, sw.migrating = r.To, false
		// Best-effort: the fast path already carries whole packets on the
		// new softwire, and only fragmentation lags if this fails.
		sw.setTunnel(r.To)
		return doneRep{}

	case beginReq:
		// The affinity counters are cumulative across the process, so
		// baseline them: what matters is whether *this* priming pass lost
		// any flow.
		c, err := sw.counts()
		if err != nil {
			return countsRep{Err: err}
		}
		if err := sw.dp.BeginMigration(r.To.B4, r.To.AFTR); err != nil {
			return countsRep{Err: err}
		}
		sw.target, sw.migrating = r.To, true
		return countsRep{Counts: c}

	case countsReq:
		c, err := sw.counts()
		return countsRep{c, err}

	case abortReq:
		if err := sw.dp.AbortMigration(); err != nil {
			return doneRep{err}
		}
		sw.migrating = false
		return doneRep{}

	case cutoverReq:
		if err := sw.dp.Cutover(); err != nil {
			return doneRep{err}
		}
		sw.active = sw.target
		// New flows are on the new AFTR, so their fragments must go through
		// it too; the draining flows' own fragments fall to the kernel with
		// the old remote until they finish (docs/rfc-compliance-backlog.md).
		sw.setTunnel(sw.target)
		return doneRep{}

	case gcReq:
		n, err := sw.dp.GCFlowAffinity(flowIdle)
		return gcRep{n, err}

	case completeReq:
		if err := sw.dp.CompleteMigration(); err != nil {
			return doneRep{err}
		}
		sw.migrating = false
		return doneRep{}
	}
	return nil
}

func (sw *Softwire) counts() (Counts, error) {
	s, err := sw.dp.Stats()
	if err != nil {
		return Counts{}, err
	}
	return Counts{s.AffinityInsert, s.AffinityInsertFail}, nil
}

func (sw *Softwire) setTunnel(ep Endpoints) {
	if err := sw.tun.SetEndpoints(ep.B4, ep.AFTR); err != nil {
		log.Printf("softwire slow path: %v", err)
	}
}
