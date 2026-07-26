package wanextend

import (
	"context"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/shun159/miniteman/pkg/routeradvert"
)

// validLifetime/preferredLifetime are the Valid/Preferred lifetimes this
// package advertises for the WAN's own SLAAC prefix when re-advertising it
// to LAN clients: RFC 4861 §6.2.1's recommended AdvValidLifetime/
// AdvPreferredLifetime defaults. The WAN-side RA that actually assigned
// this prefix carries its own (possibly different) lifetimes, but
// DiscoverPrefix/WatchChanges read the prefix back from the kernel's
// address list (pkg/netlink.Socket.Addrs), which doesn't expose
// IFA_CACHEINFO's remaining lifetimes -- a known simplification, not a
// protocol requirement.
const (
	validLifetime     = 2592000 * time.Second // 30 days
	preferredLifetime = 604800 * time.Second  // 7 days
)

// raWorker tracks one running routeradvert.Serve goroutine for a single LAN
// interface, mirroring internal/lanprefix's own raWorker/RAManager shape.
type raWorker struct {
	cancel  context.CancelFunc
	done    chan struct{}
	updates *routeradvert.Updater
}

// alive reports whether the worker's goroutine is still running -- see
// internal/lanprefix's identically-shaped raWorker.alive.
func (w *raWorker) alive() bool {
	select {
	case <-w.done:
		return false
	default:
		return true
	}
}

// raManager drives one routeradvert.Serve goroutine per LAN interface,
// broadcasting the same prefix (On-Link cleared) to all of them uniformly
// -- unlike internal/lanprefix.RAManager, which advertises a distinct
// subnet per interface, NDProxy extends one shared WAN /64 onto every LAN
// interface, so there's only ever one prefix to hand out. Not safe for
// concurrent use.
type raManager struct {
	workers      map[string]*raWorker
	rdnssByIface map[string]netip.Addr
}

// newRAManager mirrors internal/lanprefix.NewRAManager's rdnssByIface
// parameter -- see routeradvert.Config.RDNSSAddr's own doc.
func newRAManager(rdnssByIface map[string]netip.Addr) *raManager {
	return &raManager{workers: make(map[string]*raWorker), rdnssByIface: rdnssByIface}
}

// sync makes prefix the one every lanIfaces worker advertises, starting a
// worker (tracked on wg) for an interface that has none yet and updating
// the running one in place otherwise -- the same reasoning as
// internal/lanprefix.RAManager.Sync: cancelling a worker is
// routeradvert.Serve's shutdown path, which announces RouterLifetime=0 (RFC
// 4861 §6.2.5) before exiting, so restarting on a WAN prefix change would
// withdraw the default route and the RDNSS server from every LAN client for
// as long as the replacement takes to announce itself.
//
// That final RA never deprecated the *old* prefix anyway -- it carries a
// Prefix Information Option for the outgoing prefix with its lifetimes
// intact -- so nothing about renumbering is lost by not restarting. LAN
// clients keep their old SLAAC address until its own advertised valid
// lifetime runs out either way; advertising the superseded prefix with
// PreferredLifetime=0 to deprecate it promptly is RFC 9096 territory, an
// open item in docs/rfc-compliance-backlog.md.
//
// A worker that exited on its own (Serve returned an error) is replaced by
// a fresh one.
func (m *raManager) sync(ctx context.Context, prefix netip.Prefix, lanIfaces []string, wg *sync.WaitGroup) {
	for _, iface := range lanIfaces {
		cfg := m.config(iface, prefix)
		if w, ok := m.workers[iface]; ok {
			if w.alive() {
				w.updates.Set(cfg)
				continue
			}
			m.stop(iface) // dead: release its context, then replace it
		}
		m.start(ctx, iface, cfg, wg)
	}
}

// config builds the Router Advertisement configuration for one LAN
// interface: the shared WAN prefix with On-Link cleared (see the package
// doc) and this interface's RDNSS address, if any.
func (m *raManager) config(iface string, prefix netip.Prefix) routeradvert.Config {
	return routeradvert.Config{
		Prefix:            prefix,
		OnLink:            false,
		ValidLifetime:     validLifetime,
		PreferredLifetime: preferredLifetime,
		RDNSSAddr:         m.rdnssByIface[iface],
	}
}

// stop cancels and waits for iface's existing worker, if any, so at most
// one routeradvert.Serve goroutine per interface ever runs.
func (m *raManager) stop(iface string) {
	w, ok := m.workers[iface]
	if !ok {
		return
	}
	w.cancel()
	<-w.done
	delete(m.workers, iface)
}

func (m *raManager) start(ctx context.Context, iface string, cfg routeradvert.Config, wg *sync.WaitGroup) {
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	updates := routeradvert.NewUpdater()
	m.workers[iface] = &raWorker{cancel: cancel, done: done, updates: updates}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		if err := routeradvert.Serve(workerCtx, iface, cfg, updates); err != nil {
			log.Printf("wanextend: RA serving on %s ended unexpectedly: %v", iface, err)
		}
	}()
}
