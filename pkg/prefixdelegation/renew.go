package prefixdelegation

import (
	"context"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
)

// The renewal ladder of a lease (RFC 3315 §18.1.3/§18.1.4): Renew at T1
// with the server that granted it, until T2; then Rebind with any server,
// until the lease's shortest valid lifetime runs out; then Solicit afresh
// (Acquire). Its T1/T2 are the effective ones, never the server's literal 0
// (see effectiveTimers), so a server that leaves the timing to its client
// doesn't turn the ladder into a renew storm. Running the ladder -- waiting
// for each step, applying each lease -- is the caller's.

// RenewAt is when lease is to be renewed: T1 after it was granted.
func (l *Lease) RenewAt() time.Time { return l.AcquiredAt.Add(l.T1) }

// RebindAt is when lease is to be rebound, Renew having failed: T2 after it
// was granted.
func (l *Lease) RebindAt() time.Time { return l.AcquiredAt.Add(l.T2) }

// ExpiresAt is when lease, not renewed, is no longer usable: its shortest
// valid lifetime after it was granted.
func (l *Lease) ExpiresAt() time.Time { return l.AcquiredAt.Add(l.shortestValidLifetime()) }

// Renew performs one Renew exchange against lease's own server, bounded by
// ctx or lease's RebindAt (RFC 3315 §18.1.3: Renew is only valid until T2),
// whichever comes first, and returns the lease the server's Reply grants.
func Renew(ctx context.Context, ex dhcpv6.Exchanger, lease *Lease) (*Lease, error) {
	ctx, cancel := context.WithDeadline(ctx, lease.RebindAt())
	defer cancel()

	reply, err := dhcpv6.Renew(ctx, ex, dhcpv6.Options{
		{Code: dhcpv6.OptionServerID, Data: lease.ServerID},
		lease.iaPDOption(),
		requestedOptions,
	})
	if err != nil {
		return nil, err
	}
	return leaseFromReply(lease.ServerID, reply)
}

// Rebind performs one Rebind exchange, addressed to no server in particular
// (RFC 3315 §18.1.4 forbids OPTION_SERVERID on a Rebind, since it's sent
// precisely because the original server hasn't answered), bounded by ctx or
// lease's ExpiresAt -- the point RFC 3315 says the client must stop using it
// regardless -- whichever comes first.
func Rebind(ctx context.Context, ex dhcpv6.Exchanger, lease *Lease) (*Lease, error) {
	ctx, cancel := context.WithDeadline(ctx, lease.ExpiresAt())
	defer cancel()

	reply, err := dhcpv6.Rebind(ctx, ex, dhcpv6.Options{lease.iaPDOption(), requestedOptions})
	if err != nil {
		return nil, err
	}
	return leaseFromReply(nil, reply)
}

// leaseFromReply extracts a usable IA_PD from a Renew/Rebind Reply and
// builds the resulting Lease. serverID is the one to keep using for future
// Renews; pass nil (as Rebind does) to take whatever the Reply itself
// carries.
//
// The renewed Lease takes its DNS servers from this Reply, so a server that
// changes them mid-lease is followed. A Reply carrying none leaves
// Lease.DNSServers nil rather than inheriting the previous lease's: the
// renewal exchanges carry the same ORO as the original Acquire, so silence
// here is the server declining to answer a question it was asked, not a
// question that went unasked.
func leaseFromReply(serverID dhcpv6.DUID, reply *dhcpv6.Message) (*Lease, error) {
	granted, replyServerID, err := usableIAPD(reply)
	if err != nil {
		return nil, err
	}
	if serverID == nil {
		serverID = replyServerID
	}
	dnsServers, _, err := reply.Options.DNSServers()
	if err != nil {
		dnsServers = nil
	}
	return newLease(serverID, granted, dnsServers), nil
}

// Release sends a Release for lease (RFC 3315 §18.1.6), bounded by ctx. A
// client stops using a binding locally whether or not the server ever
// acknowledges it, so a caller shutting down treats a failure as
// best-effort, not as something to wait out.
func Release(ctx context.Context, ex dhcpv6.Exchanger, lease *Lease) error {
	return dhcpv6.Release(ctx, ex, dhcpv6.Options{
		{Code: dhcpv6.OptionServerID, Data: lease.ServerID},
		lease.iaPDOption(),
	})
}
