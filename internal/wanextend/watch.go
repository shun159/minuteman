package wanextend

import (
	"log"
	"net/netip"

	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/proc"
)

// WatchName is the name of the watch process.
const WatchName molecule.Local = "wanextend watch"

// Config is what the WAN prefix is extended onto, and how.
type Config struct {
	WANIndex int      // the WAN interface, whose prefix is extended
	LANs     []string // the interfaces it is extended onto
	// RDNSS is forwarded to every LAN interface's routeradvert.Config (see
	// its RDNSSAddr doc) -- it maps a LAN interface to the DNS-server
	// address a DNS proxy actually bound there, so it's non-empty only
	// when the caller also runs a DNS proxy on those interfaces'
	// link-local addresses.
	RDNSS map[string]netip.Addr
	Adv   Advertiser
}

// Extend has every LAN interface advertise prefix, the WAN's, with On-Link
// cleared (see routeradvert.Config.OnLink's doc). The caller extends the
// prefix DiscoverPrefix found, then starts Spec's watch, which extends each
// prefix after it.
func (c Config) Extend(prefix netip.Prefix) {
	newRAManager(c.Adv, c.RDNSS).sync(prefix, c.LANs)
}

// Spec is the supervision tree watching the WAN prefix extended, prefix,
// for a renumbering:
//
//	wanextend (one_for_one)
//	└── wanextend watch   genserver: re-reads the WAN prefix on a timer
//
// The proxy itself -- answering the WAN's Neighbor Solicitations,
// installing a confirmed host's route -- is internal/ndppd's, which the
// caller runs.
func Spec(cfg Config, prefix netip.Prefix) supervisor.Spec {
	w := watcher{
		cfg: cfg, initial: prefix, logf: log.Printf,
		read: func() (netip.Prefix, error) { return discoverPrefixOnce(cfg.WANIndex) },
	}
	return supervisor.Spec{
		Name:     molecule.Local("wanextend"),
		Strategy: supervisor.OneForOne,
		Children: []supervisor.ChildSpec{
			{ID: "wanextend watch", Start: genserver.Child(w, molecule.WithName(WatchName))},
		},
	}
}

// tick is the message of the watch timer.
type tick struct{}

// watcher re-reads the WAN prefix every watchPollInterval, and extends it
// anew when it has changed. Its state is the prefix extended. It is where
// the kernel's address list meets the RAs, and so not pure: each tick is a
// netlink dump and, on a change, casts to the advertisers. Whether a
// reading is a change is nextWatchState's.
//
// It starts from the prefix the caller extended, reading the WAN at once: a
// restarted watch, which doesn't know what its last incarnation extended,
// so extends a prefix the WAN has meanwhile changed to.
type watcher struct {
	genserver.Default[netip.Prefix]
	cfg     Config
	initial netip.Prefix
	read    func() (netip.Prefix, error)
	logf    func(format string, args ...any)
}

func (w watcher) Init(proc.PID) (netip.Prefix, []molecule.Effect, error) {
	return w.initial, molecule.Do(molecule.StartTimer{Key: tick{}, Msg: tick{}}), nil
}

func (w watcher) HandleInfo(current netip.Prefix, msg any) (netip.Prefix, []molecule.Effect) {
	if _, ok := msg.(tick); !ok {
		return current, nil
	}
	next, err := w.read()
	if updated, changed := nextWatchState(current, next, err); changed {
		w.logf("NDProxy: WAN prefix changed to %s, re-extending onto %d LAN interface(s)", updated, len(w.cfg.LANs))
		w.cfg.Extend(updated)
		current = updated
	}
	return current, molecule.Do(molecule.StartTimer{Key: tick{}, After: watchPollInterval, Msg: tick{}})
}
