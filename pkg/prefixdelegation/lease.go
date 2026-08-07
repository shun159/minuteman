package prefixdelegation

import (
	"net/netip"
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
//
// T1/T2 are the timers actually in effect, not necessarily the ones the
// server sent: a server may leave either to the client's discretion by
// sending 0, in which case effectiveTimers has picked the value (RFC 9915
// §14.2).
type Lease struct {
	ServerID dhcpv6.DUID
	Prefixes []IAPrefix
	T1, T2   time.Duration

	// DNSServers is OPTION_DNS_SERVERS from the granting Reply (RFC 3646),
	// nil if the server sent none. It has nothing to do with the delegation
	// itself; it's here because this exchange is the only one that learns it
	// on a network that doesn't answer Information-Request, and a caller
	// that needs a resolver before it has one has nowhere else to look.
	DNSServers []netip.Addr

	AcquiredAt time.Time
}

// newLease builds the Lease a granted IA_PD represents, resolving the
// renewal timers to run it on through effectiveTimers.
func newLease(serverID dhcpv6.DUID, iapd *IAPD, dnsServers []netip.Addr) *Lease {
	t1, t2 := effectiveTimers(iapd)
	return &Lease{
		ServerID:   serverID,
		Prefixes:   iapd.Prefixes,
		T1:         t1,
		T2:         t2,
		DNSServers: dnsServers,
		AcquiredAt: time.Now(),
	}
}

// shortestValidLifetime returns the smallest ValidLifetime across l's
// delegated prefixes -- the point by which RFC 3315 §18.1.4 says a client
// must stop using a binding if Rebind hasn't succeeded by then.
func (l *Lease) shortestValidLifetime() time.Duration {
	return shortestValidLifetime(l.Prefixes)
}

// iaPDOption rebuilds l's delegated IA_PD as an OPTION_IA_PD, for echoing
// back in Renew/Rebind/Release requests.
//
// T1/T2 go out as 0: RFC 9915 §21.21 says a client SHOULD zero them in
// messages to the server, which MUST ignore them regardless. Echoing l's
// own timers back would be doubly wrong now that they may be values this
// client derived rather than ones the server chose (see effectiveTimers).
func (l *Lease) iaPDOption() dhcpv6.Option {
	return IAPDOption(IAPD{
		IAID:     clientIAID,
		Prefixes: l.Prefixes,
	})
}
