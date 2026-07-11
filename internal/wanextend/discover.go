// Package wanextend implements the CPE-policy decisions for RFC 4389
// Neighbor Discovery Proxy: when an ISP hands out a single on-link /64 on
// the WAN interface with no DHCPv6-PD delegation (see internal/lanprefix
// for the alternative, distinct-delegation model), this package learns
// that /64 (DiscoverPrefix), keeps watching for it changing (WatchChanges
// -- an ISP renumbering the WAN link), re-advertises it on every LAN
// interface with On-Link cleared so LAN clients route everything -- not
// just off-/64 traffic -- through this CPE, and maintains per-host routes
// (HostRoutes) so the kernel forwards a target's traffic out the correct
// LAN interface once pkg/ndproxy.Serve confirms it's actually there.
// Serve ties all of this together into the single call cmd/minuteman
// makes for -ndproxy.
package wanextend

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/shun159/miniteman/pkg/netlink"
)

// prefixPollInterval is how often DiscoverPrefix retries reading the WAN
// interface's addresses while waiting for SLAAC to land -- RA/SLAAC
// resolves within a couple of seconds of the router solicitation
// pkg/datapath's AttachWAN and cmd/minuteman's SolicitRouters call
// trigger, so this isn't tuned to a particular RFC cadence, just to notice
// quickly without busy-polling.
const prefixPollInterval = 2 * time.Second

// watchPollInterval is how often WatchChanges re-checks the WAN interface's
// address for a renumbering, once the initial prefix is already known.
// Unlike prefixPollInterval, there's no "just came up" urgency here -- an
// ISP renumbering a WAN /64 is rare and RFC 4861 attaches no cadence a CPE
// actively drives for noticing it (unlike DHCPv6-PD's T1/T2: the kernel
// just manages its own address lifetimes from whatever RAs happen to
// arrive, so this package can only notice a change after the fact). Five
// minutes is a CPE-local policy choice, not an RFC requirement.
const watchPollInterval = 5 * time.Minute

// DiscoverPrefix blocks until wanIfindex has a global-scope IPv6 address
// assigned to report (via pkg/netlink.Socket.Addrs), retrying every
// prefixPollInterval -- RA/SLAAC lands asynchronously sometime after the
// WAN link comes up, and the caller has nothing to extend onto the LAN
// (NDProxy's whole premise) until it does. Returns ctx's error if
// cancelled first. The returned Prefix is masked to its network (host bits
// zeroed), ready to hand to pkg/routeradvert.Config.Prefix. If more than
// one global address is assigned, the first one Addrs reports is used --
// the kernel doesn't order these meaningfully, but a WAN link with more
// than one SLAAC prefix is outside this package's model (see the package
// doc).
func DiscoverPrefix(ctx context.Context, wanIfindex int) (netip.Prefix, error) {
	for {
		prefix, err := discoverPrefixOnce(wanIfindex)
		if err == nil {
			return prefix, nil
		}

		select {
		case <-ctx.Done():
			return netip.Prefix{}, ctx.Err()
		case <-time.After(prefixPollInterval):
		}
	}
}

func discoverPrefixOnce(wanIfindex int) (netip.Prefix, error) {
	sock, err := netlink.Open()
	if err != nil {
		return netip.Prefix{}, err
	}
	defer sock.Close()

	addrs, err := sock.Addrs(wanIfindex)
	if err != nil {
		return netip.Prefix{}, err
	}
	if len(addrs) == 0 {
		return netip.Prefix{}, fmt.Errorf("wanextend: no global-scope address on ifindex %d yet", wanIfindex)
	}
	return addrs[0].Masked(), nil
}

// WatchChanges blocks until ctx is cancelled, polling every
// watchPollInterval and calling onChange whenever wanIfindex's
// global-scope SLAAC prefix differs from current -- e.g. after the ISP
// renumbers the WAN link. current is the caller's already-known baseline
// (typically DiscoverPrefix's own return value): onChange never fires for
// it, only for a later, different reading. A read that errors or comes
// back empty (the WAN briefly having no global address mid-renumbering,
// or a transient netlink failure) is not itself reported -- current is
// kept and re-advertised until a genuinely different prefix is confirmed,
// the same conservative choice pkg/routeradvert's EADDRNOTAVAIL retry
// makes for a tentative address, rather than tearing down a working
// advertisement over a one-tick blip.
func WatchChanges(ctx context.Context, wanIfindex int, current netip.Prefix, onChange func(netip.Prefix)) error {
	ticker := time.NewTicker(watchPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			next, err := discoverPrefixOnce(wanIfindex)
			if updated, changed := nextWatchState(current, next, err); changed {
				current = updated
				onChange(current)
			}
		}
	}
}

// nextWatchState is WatchChanges' per-tick decision, split out so it's
// tested without a real clock or netlink socket: given the currently
// known prefix and one fresh reading (next, err, exactly as
// discoverPrefixOnce returns them), report whether that reading is a real,
// reportable change.
func nextWatchState(current, next netip.Prefix, err error) (updated netip.Prefix, changed bool) {
	if err != nil || !next.IsValid() || next == current {
		return current, false
	}
	return next, true
}
