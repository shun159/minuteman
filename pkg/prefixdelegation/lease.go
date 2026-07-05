package prefixdelegation

import (
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
)

// clientIAID identifies minuteman's single prefix-delegation IA across
// restarts. It's fixed rather than derived per-run (e.g. from the WAN
// ifindex, which can change across reboots on some systems) so the server
// has the best chance of handing back the same delegated prefix every time,
// avoiding LAN renumbering -- the same rationale pkg/dhcpv6/duid.go gives
// for regenerating a stable DUID-LL from the interface MAC instead of a
// persisted DUID-LLT.
var clientIAID = [4]byte{0, 0, 0, 1}

// Lease is the outcome of a successful DHCPv6-PD exchange (RFC 3633): the
// delegating server's DUID (required to address Renew/Release to the same
// server) plus the delegated prefixes and their T1/T2 renewal timers.
type Lease struct {
	ServerID   dhcpv6.DUID
	Prefixes   []IAPrefix
	T1, T2     time.Duration
	AcquiredAt time.Time
}

// shortestValidLifetime returns the smallest ValidLifetime across l's
// delegated prefixes -- the point by which RFC 3315 §18.1.4 says a client
// must stop using a binding if Rebind hasn't succeeded by then.
func (l *Lease) shortestValidLifetime() time.Duration {
	shortest := l.Prefixes[0].ValidLifetime
	for _, p := range l.Prefixes[1:] {
		if p.ValidLifetime < shortest {
			shortest = p.ValidLifetime
		}
	}
	return shortest
}

// iaPDOption rebuilds l's delegated IA_PD as an OPTION_IA_PD, for echoing
// back in Renew/Rebind/Release requests.
func (l *Lease) iaPDOption() dhcpv6.Option {
	return IAPDOption(IAPD{
		IAID:     clientIAID,
		T1:       l.T1,
		T2:       l.T2,
		Prefixes: l.Prefixes,
	})
}
