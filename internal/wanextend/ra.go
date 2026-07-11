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
	cancel context.CancelFunc
	done   chan struct{}
}

// raManager drives one routeradvert.Serve goroutine per LAN interface,
// broadcasting the same prefix (On-Link cleared) to all of them uniformly
// -- unlike internal/lanprefix.RAManager, which advertises a distinct
// subnet per interface, NDProxy extends one shared WAN /64 onto every LAN
// interface, so there's only ever one prefix to hand out. Not safe for
// concurrent use.
type raManager struct {
	workers map[string]*raWorker
}

func newRAManager() *raManager {
	return &raManager{workers: make(map[string]*raWorker)}
}

// sync restarts every lanIfaces worker to advertise prefix, tracking each
// on wg. Always restarts, matching internal/lanprefix.RAManager.Sync's own
// "restarting is cheap" reasoning -- callers only invoke this from
// WatchChanges' onChange (or once, from Serve's initial known prefix), so
// there's no risk of restarting on an unchanged value in practice.
func (m *raManager) sync(ctx context.Context, prefix netip.Prefix, lanIfaces []string, wg *sync.WaitGroup) {
	for _, iface := range lanIfaces {
		m.stop(iface)
		m.start(ctx, iface, prefix, wg)
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

func (m *raManager) start(ctx context.Context, iface string, prefix netip.Prefix, wg *sync.WaitGroup) {
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	m.workers[iface] = &raWorker{cancel: cancel, done: done}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		err := routeradvert.Serve(workerCtx, iface, routeradvert.Config{
			Prefix:            prefix,
			OnLink:            false,
			ValidLifetime:     validLifetime,
			PreferredLifetime: preferredLifetime,
		})
		if err != nil {
			log.Printf("wanextend: RA serving on %s ended unexpectedly: %v", iface, err)
		}
	}()
}
