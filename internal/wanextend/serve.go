package wanextend

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync"
)

// Serve runs the -ndproxy CPE policy for lanIfaces: blocks on the initial
// DiscoverPrefix (there's nothing to advertise until at least one WAN prefix
// is known, the same rationale cmd/minuteman's runPrefixDelegation applies
// to its own initial Acquire), has adv advertise it on every LAN interface,
// then starts a WatchChanges loop, registered on wg, having adv advertise
// the new prefix if the WAN's changes. The proxy itself -- answering the
// WAN's Neighbor Solicitations, installing a confirmed host's route -- is
// internal/ndppd's, which the caller runs. A non-nil return means the
// initial discovery failed or was cancelled; once past that point, Serve
// returns nil and leaves the watch running until ctx is cancelled.
//
// rdnssByIface is forwarded to every LAN interface's routeradvert.Config
// (see its RDNSSAddr doc) -- it maps a -lan interface to the DNS-server
// address a DNS proxy actually bound there, so it's non-empty only when the
// caller also runs a DNS proxy on those interfaces' link-local addresses.
func Serve(ctx context.Context, wanIfindex int, lanIfaces []string, rdnssByIface map[string]netip.Addr, adv Advertiser, wg *sync.WaitGroup) error {
	prefix, err := DiscoverPrefix(ctx, wanIfindex)
	if err != nil {
		return fmt.Errorf("discovering WAN prefix for NDProxy: %w", err)
	}

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
