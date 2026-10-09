package lanprefix

import (
	"context"
	"log"
	"net/netip"
	"sync"

	"github.com/shun159/miniteman/pkg/routeradvert"
)

// raWorker tracks one running routeradvert.Serve goroutine for a single LAN
// interface: cancel stops it, done is closed once it has actually returned
// (after sending its final RA), and updates hands it a new configuration
// while it keeps running.
type raWorker struct {
	cancel  context.CancelFunc
	done    chan struct{}
	updates *routeradvert.Updater
}

// alive reports whether the worker's goroutine is still running. It only
// isn't when Serve returned an error on its own (a socket failure -- see
// start's log line), since nothing else cancels a worker except stop.
func (w *raWorker) alive() bool {
	select {
	case <-w.done:
		return false
	default:
		return true
	}
}

// RAManager drives one routeradvert.Serve goroutine per LAN interface,
// advertising each interface's currently-assigned /64 (see Assignment) to
// LAN clients via Router Advertisements. Not safe for concurrent use.
type RAManager struct {
	workers      map[string]*raWorker
	rdnssByIface map[string]netip.Addr
}

// NewRAManager returns an RAManager with no workers running yet.
// rdnssByIface maps a LAN interface name to the DNS-server address to
// advertise in its RAs' RDNSS option (RFC 8106) -- it must be an address a
// DNS proxy actually bound (see routeradvert.Config.RDNSSAddr's own doc), so
// the caller passes exactly the link-local addresses internal/dnsproxy reported
// binding. An interface absent from the map (or a nil map) gets no RDNSS.
func NewRAManager(rdnssByIface map[string]netip.Addr) *RAManager {
	return &RAManager{workers: make(map[string]*raWorker), rdnssByIface: rdnssByIface}
}

// Sync makes every assigned entry with a valid Subnet the configuration
// advertised on its interface, starting a routeradvert.Serve goroutine
// (registered on wg) for an interface that has none yet and updating the
// running one in place otherwise.
//
// Updating in place matters because a DHCPv6-PD Renew resets ValidLifetime/
// PreferredLifetime on every lease change, so Sync is reached on every T1
// interval even when nothing about the subnet changed. Cancelling the
// worker and starting a fresh one would deliver those refreshed lifetimes
// too, but cancellation is routeradvert.Serve's shutdown path: it sends RFC
// 4861 §6.2.5's RouterLifetime=0 (plus RDNSS Lifetime=0) advertisement
// first, so every LAN client would see its default route and DNS server
// withdrawn once per renewal and reinstated a moment later. See
// routeradvert.Updater.
//
// A worker that exited on its own (Serve returned an error) is replaced by
// a fresh one, so a transient socket failure doesn't leave an interface
// silently unadvertised until the next restart.
//
// Entries whose Subnet is invalid (Reconcile failed for that interface) are
// left alone -- any previously-running worker for that interface keeps
// running rather than being torn down over a transient error.
func (m *RAManager) Sync(ctx context.Context, assigned []Assignment, wg *sync.WaitGroup) {
	for _, a := range assigned {
		if !a.Subnet.IsValid() {
			continue
		}
		cfg := m.config(a)
		if w, ok := m.workers[a.Iface]; ok {
			if w.alive() {
				w.updates.Set(cfg)
				continue
			}
			m.stop(a.Iface) // dead: release its context, then replace it
		}
		m.start(ctx, a.Iface, cfg, wg)
	}
}

// config builds the Router Advertisement configuration for one assigned
// interface.
func (m *RAManager) config(a Assignment) routeradvert.Config {
	return routeradvert.Config{
		Prefix: a.Subnet,
		// DHCPv6-PD delegates this /64 distinctly to this LAN
		// interface, so it really is on-link for it -- unlike
		// internal/wanextend's NDProxy model, which shares one
		// prefix across WAN and LAN and must clear this.
		OnLink:            true,
		ValidLifetime:     a.ValidLifetime,
		PreferredLifetime: a.PreferredLifetime,
		RDNSSAddr:         m.rdnssByIface[a.Iface],
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

func (m *RAManager) start(ctx context.Context, iface string, cfg routeradvert.Config, wg *sync.WaitGroup) {
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	updates := routeradvert.NewUpdater()
	m.workers[iface] = &raWorker{cancel: cancel, done: done, updates: updates}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		if err := routeradvert.Serve(workerCtx, iface, cfg, updates); err != nil {
			log.Printf("lanprefix: RA serving on %s ended unexpectedly: %v", iface, err)
		}
	}()
}
