package wanextend

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync"

	"github.com/shun159/miniteman/pkg/ndproxy"
)

// Serve runs the -ndproxy CPE policy for wanIface/lanIfaces: blocks on the
// initial DiscoverPrefix (there's nothing to start until at least one WAN
// prefix is known, the same rationale cmd/minuteman's runPrefixDelegation
// applies to its own initial Acquire), then starts every background
// goroutine -- a WatchChanges loop that has adv advertise the new prefix if
// the WAN prefix later changes, and pkg/ndproxy.Serve itself on wanIface
// with a HostRoutes-backed OnActive/OnInactive -- registering each on wg so
// the caller can wait for shutdown's best-effort cleanup (ndproxy's socket
// closes) to finish before returning. The LAN Router Advertisements are
// adv's, an advertiser per lanIfaces interface (internal/radvd). A non-nil return means the
// initial discovery failed or was cancelled; once past that point, Serve
// itself always returns nil and leaves its goroutines running until ctx is
// cancelled.
//
// rdnssByIface is forwarded to every LAN interface's routeradvert.Config
// (see its RDNSSAddr doc) -- it maps a -lan interface to the DNS-server
// address a DNS proxy actually bound there, so it's non-empty only when the
// caller also runs a DNS proxy on those interfaces' link-local addresses.
func Serve(ctx context.Context, wanIface string, wanIfindex int, lanIfaces []string, rdnssByIface map[string]netip.Addr, adv Advertiser, wg *sync.WaitGroup) error {
	prefix, err := DiscoverPrefix(ctx, wanIfindex)
	if err != nil {
		return fmt.Errorf("discovering WAN prefix for NDProxy: %w", err)
	}

	hostRoutes, err := NewHostRoutes()
	if err != nil {
		return fmt.Errorf("opening NDProxy host-route socket: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer hostRoutes.Close()
		err := ndproxy.Serve(ctx, wanIface, lanIfaces, ndproxy.Config{
			OnActive: func(target netip.Addr, iface string) error {
				log.Printf("NDProxy: %s confirmed active behind %s", target, iface)
				return hostRoutes.Install(target, iface)
			},
			OnInactive: func(target netip.Addr, iface string) {
				log.Printf("NDProxy: %s behind %s expired", target, iface)
				hostRoutes.Remove(target, iface)
			},
		})
		if err != nil {
			log.Printf("NDProxy: Serve on %s ended unexpectedly: %v", wanIface, err)
		}
	}()

	ra := newRAManager(adv, rdnssByIface)
	log.Printf("NDProxy: extending WAN prefix %s onto %d LAN interface(s)", prefix, len(lanIfaces))
	ra.sync(prefix, lanIfaces)

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := WatchChanges(ctx, wanIfindex, prefix, func(next netip.Prefix) {
			log.Printf("NDProxy: WAN prefix changed to %s, re-extending onto %d LAN interface(s)", next, len(lanIfaces))
			ra.sync(next, lanIfaces)
		})
		if err != nil {
			log.Printf("NDProxy: WAN prefix watch on ifindex %d ended unexpectedly: %v", wanIfindex, err)
		}
	}()

	return nil
}
