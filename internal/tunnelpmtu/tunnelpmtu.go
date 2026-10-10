// Package tunnelpmtu keeps the two userspace-owned consequences of a
// learned softwire path MTU in step with what the datapath has learned from
// ICMPv6 Packet Too Big messages about its own tunnel packets (RFC 2473 §8,
// see handle_tunnel_icmpv6): the in-XDP fragmenter's per-fragment payload
// size, and the companion ip6tnl's MTU (which governs the fallback paths'
// inner-IPv4 fragmentation). It is a molecule process, polling the datapath
// on a timer.
//
// Deriving the fragment size here rather than in the datapath is
// deliberate: encap_fragment_outer and the xdp_softwire_frag<i> programs
// read frag_unit at different moments for the same packet, so a value that
// changed in between would yield a fragment set that can never reassemble.
// The encap stage snapshots that configured unit into each clone; companion
// stages use the snapshot even when this process updates the configuration
// in flight.
//
// It also handles the widening direction: TunnelPMTU stops reporting an
// aged-out reading, so the fragment size and the tunnel MTU go back to the
// WAN device's own without needing any packet to announce that the narrow
// path is gone.
package tunnelpmtu

import (
	"log"
	"time"

	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/proc"
)

// PollInterval is how often the learned softwire path MTU is checked for a
// change. The datapath needs no such poll -- encap clamps against the
// learned value per packet the moment it lands (see tunnel_pmtu_for) -- so
// this only paces the two things userspace owns. A couple of seconds of lag
// on those costs a handful of packets the ip6tnl fallback carries instead
// of the in-XDP fragmenter, which is the designed degradation, not a
// failure.
const PollInterval = 2 * time.Second

// Name is the name of the process.
const Name molecule.Local = "tunnel pmtu"

// Datapath is what the process reads the learned path MTU from, and
// applies the fragment size to: pkg/datapath's Loader.
type Datapath interface {
	TunnelPMTU() (mtu uint32, ok bool)
	SetSoftwireMTU(mtu int) error
}

// Tunnel is the companion ip6tnl: internal/slowpath's Tunnel.
type Tunnel interface {
	SetSoftwireMTU(mtu int) error
}

// Config configures the process.
type Config struct {
	Datapath Datapath
	Tunnel   Tunnel
	// WANMTU is the WAN device's MTU: the path MTU when none is learned.
	WANMTU int
}

// Spec is the supervision tree of the process:
//
//	tunnelpmtu (one_for_one)
//	└── tunnel pmtu   genserver: polls the datapath, applies the path MTU
func Spec(cfg Config) supervisor.Spec {
	w := watcher{cfg: cfg, logf: log.Printf}
	return supervisor.Spec{
		Name:     molecule.Local("tunnelpmtu"),
		Strategy: supervisor.OneForOne,
		Children: []supervisor.ChildSpec{
			{ID: "tunnel pmtu", Start: genserver.Child(w, molecule.WithName(Name))},
		},
	}
}

// tick is the message of the poll timer.
type tick struct{}

// state is what the process has applied, tracked apart so that a failure
// on one doesn't strand the other at a stale value: whichever didn't take
// is retried on the next tick, while the one that did stays a no-op. Zero
// is not known, applied on the first tick -- a restarted process doesn't
// know what its last incarnation applied. reported is the path MTU last
// logged.
type state struct {
	frag, tunnel int
	reported     int
}

// watcher polls the datapath and applies the path MTU it has learned. It is
// where the datapath's learning meets the fragmenter's configuration and
// the ip6tnl, and so not pure: each tick reads a BPF map and writes what
// changed, as it is handled -- a map lookup and, rarely, a map update and a
// netlink request. What to apply is effective's.
type watcher struct {
	genserver.Default[state]
	cfg  Config
	logf func(format string, args ...any)
}

func (w watcher) Init(proc.PID) (state, []molecule.Effect, error) {
	return state{reported: w.cfg.WANMTU}, molecule.Do(w.next(0)), nil
}

func (w watcher) HandleInfo(st state, msg any) (state, []molecule.Effect) {
	if _, ok := msg.(tick); !ok {
		return st, nil
	}
	learned, ok := w.cfg.Datapath.TunnelPMTU()
	mtu := effective(w.cfg.WANMTU, learned, ok)
	if mtu != st.frag {
		if err := w.cfg.Datapath.SetSoftwireMTU(mtu); err != nil {
			w.logf("softwire path MTU: applying %d to the fragmenter: %v", mtu, err)
		} else {
			st.frag = mtu
		}
	}
	if mtu != st.tunnel {
		// Best-effort, like every other runtime update to this device: the
		// fast path has already adapted.
		if err := w.cfg.Tunnel.SetSoftwireMTU(mtu); err != nil {
			w.logf("softwire path MTU: %v", err)
		} else {
			st.tunnel = mtu
		}
	}
	// Log the reading, once it has taken, not each attempt: a failure
	// above logged itself.
	if st.frag == mtu && mtu != st.reported {
		st.reported = mtu
		if mtu < w.cfg.WANMTU {
			w.logf("softwire path MTU: %d (learned from an ICMPv6 Packet Too Big; WAN MTU is %d)", mtu, w.cfg.WANMTU)
		} else {
			w.logf("softwire path MTU: back to the WAN MTU (%d)", w.cfg.WANMTU)
		}
	}
	return st, molecule.Do(w.next(PollInterval))
}

func (w watcher) next(after time.Duration) molecule.Effect {
	return molecule.StartTimer{Key: tick{}, After: after, Msg: tick{}}
}

// effective is the path MTU to apply: the learned one, if any and narrower
// than the WAN's, else the WAN's.
func effective(wanMTU int, learned uint32, ok bool) int {
	if ok && int(learned) < wanMTU {
		return int(learned)
	}
	return wanMTU
}
