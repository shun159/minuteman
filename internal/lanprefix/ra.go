package lanprefix

import (
	"context"
	"log"
	"sync"

	"github.com/shun159/miniteman/pkg/routeradvert"
)

// raWorker tracks one running routeradvert.Serve goroutine for a single LAN
// interface: cancel stops it, done is closed once it has actually returned
// (after sending its final RA).
type raWorker struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// RAManager drives one routeradvert.Serve goroutine per LAN interface,
// advertising each interface's currently-assigned /64 (see Assignment) to
// LAN clients via Router Advertisements. Not safe for concurrent use.
type RAManager struct {
	workers map[string]*raWorker
}

// NewRAManager returns an RAManager with no workers running yet.
func NewRAManager() *RAManager {
	return &RAManager{workers: make(map[string]*raWorker)}
}

// Sync starts (or restarts) a routeradvert.Serve goroutine for every
// assigned entry with a valid Subnet, registering each on wg. It always
// restarts rather than skipping interfaces whose Subnet is unchanged since
// the last Sync call: a DHCPv6-PD Renew resets ValidLifetime/
// PreferredLifetime to fresh values even when the Subnet itself doesn't
// change, and a long-lived Serve goroutine has no other way to pick up that
// change. Restarting is cheap (Serve's own startup cost is just opening a
// raw socket), unlike Reconcile's netlink unchanged-skip optimization,
// which exists to avoid transient route churn that restarting an RA sender
// doesn't have an equivalent of.
//
// Entries whose Subnet is invalid (Reconcile failed for that interface) are
// left alone -- any previously-running worker for that interface keeps
// running rather than being torn down over a transient error.
func (m *RAManager) Sync(ctx context.Context, assigned []Assignment, wg *sync.WaitGroup) {
	for _, a := range assigned {
		if !a.Subnet.IsValid() {
			continue
		}
		m.stop(a.Iface)
		m.start(ctx, a, wg)
	}
}

// stop cancels and waits for iface's existing worker, if any, so at most
// one routeradvert.Serve goroutine per interface ever runs.
func (m *RAManager) stop(iface string) {
	w, ok := m.workers[iface]
	if !ok {
		return
	}
	w.cancel()
	<-w.done
	delete(m.workers, iface)
}

func (m *RAManager) start(ctx context.Context, a Assignment, wg *sync.WaitGroup) {
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	m.workers[a.Iface] = &raWorker{cancel: cancel, done: done}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		err := routeradvert.Serve(workerCtx, a.Iface, routeradvert.Config{
			Prefix:            a.Subnet,
			ValidLifetime:     a.ValidLifetime,
			PreferredLifetime: a.PreferredLifetime,
		})
		if err != nil {
			log.Printf("lanprefix: RA serving on %s ended unexpectedly: %v", a.Iface, err)
		}
	}()
}
