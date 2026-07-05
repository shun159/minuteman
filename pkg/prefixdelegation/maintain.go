package prefixdelegation

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
)

// Maintain keeps lease alive on ifaceName indefinitely, following RFC 3315's
// renewal ladder: Renew at T1, falling back to Rebind at T2 if Renew never
// gets an answer, falling back to a fresh Acquire if Rebind doesn't either
// (RFC 3315 §18.1.3/§18.1.4). lease is mutated in place as it's renewed.
//
// onLeaseChange is called every time the lease actually changes -- a
// successful Renew/Rebind, or a fresh Acquire -- but not for the lease
// passed in; callers are expected to have already applied that one
// themselves before calling Maintain.
//
// Blocks until ctx is cancelled, at which point it sends Release (RFC 3315
// §18.1.6, best-effort: failures are logged, not returned) before
// returning. Returns nil on a clean ctx-cancelled shutdown; a non-nil error
// only indicates a bug (Acquire itself already retries indefinitely and
// only returns on ctx cancellation).
func Maintain(ctx context.Context, ifaceName string, lease *Lease, onLeaseChange func(*Lease)) error {
	defer releaseLease(ifaceName, lease)

	for {
		if err := sleepUntil(ctx, lease.AcquiredAt.Add(lease.T1)); err != nil {
			return nil
		}

		if renewed, err := tryRenew(ctx, ifaceName, lease); err == nil {
			*lease = *renewed
			onLeaseChange(lease)
			continue
		} else if ctx.Err() != nil {
			return nil
		}

		if rebound, err := tryRebind(ctx, ifaceName, lease); err == nil {
			*lease = *rebound
			onLeaseChange(lease)
			continue
		} else if ctx.Err() != nil {
			return nil
		}

		fresh, err := Acquire(ctx, ifaceName)
		if err != nil {
			// Acquire only returns an error on ctx cancellation.
			return nil
		}
		*lease = *fresh
		onLeaseChange(lease)
	}
}

// tryRenew performs one Renew exchange against lease's original server,
// bounded by ctx or lease's T2 (RFC 3315 §18.1.3: Renew is only valid until
// T2), whichever comes first.
func tryRenew(ctx context.Context, ifaceName string, lease *Lease) (*Lease, error) {
	renewCtx, cancel := context.WithDeadline(ctx, lease.AcquiredAt.Add(lease.T2))
	defer cancel()

	reply, err := dhcpv6.Renew(renewCtx, ifaceName, dhcpv6.Options{
		{Code: dhcpv6.OptionServerID, Data: lease.ServerID},
		lease.iaPDOption(),
	})
	if err != nil {
		return nil, err
	}
	return leaseFromReply(lease.ServerID, reply)
}

// tryRebind performs one Rebind exchange, addressed to no server in
// particular (RFC 3315 §18.1.4 forbids OPTION_SERVERID on a Rebind, since
// it's sent precisely because the original server hasn't answered),
// bounded by ctx or the binding's shortest remaining valid lifetime,
// whichever comes first -- the point RFC 3315 says the client must stop
// using it regardless.
func tryRebind(ctx context.Context, ifaceName string, lease *Lease) (*Lease, error) {
	rebindCtx, cancel := context.WithDeadline(ctx, lease.AcquiredAt.Add(lease.shortestValidLifetime()))
	defer cancel()

	reply, err := dhcpv6.Rebind(rebindCtx, ifaceName, dhcpv6.Options{lease.iaPDOption()})
	if err != nil {
		return nil, err
	}
	return leaseFromReply(nil, reply)
}

// leaseFromReply extracts a usable IA_PD from a Renew/Rebind Reply and
// builds the resulting Lease. serverID is the one to keep using for future
// Renews; pass nil (as tryRebind does) to take whatever the Reply itself
// carries.
func leaseFromReply(serverID dhcpv6.DUID, reply *dhcpv6.Message) (*Lease, error) {
	granted, replyServerID, err := usableIAPD(reply)
	if err != nil {
		return nil, err
	}
	if serverID == nil {
		serverID = replyServerID
	}
	return &Lease{
		ServerID:   serverID,
		Prefixes:   granted.Prefixes,
		T1:         granted.T1,
		T2:         granted.T2,
		AcquiredAt: time.Now(),
	}, nil
}

// releaseLease sends a best-effort Release for lease (RFC 3315 §18.1.6): a
// client stops using a binding locally regardless of whether the server
// ever acknowledges it, so failures here are logged, not propagated -- they
// must not block shutdown.
func releaseLease(ifaceName string, lease *Lease) {
	// Release must not inherit Maintain's (already-cancelled) ctx, or it
	// would never get to send even a single attempt.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := dhcpv6.Release(ctx, ifaceName, dhcpv6.Options{
		{Code: dhcpv6.OptionServerID, Data: lease.ServerID},
		lease.iaPDOption(),
	})
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		log.Printf("prefixdelegation: releasing lease on %s: %v", ifaceName, err)
	}
}

// sleepUntil sleeps until t, returning early with ctx.Err() if ctx is
// cancelled first. Mirrors pkg/dhcpv6's private sleepCtx helper; duplicated
// here rather than exported from pkg/dhcpv6 since it's a few lines and
// exporting it would widen that package's API for no real reuse benefit
// beyond this one caller.
func sleepUntil(ctx context.Context, t time.Time) error {
	d := time.Until(t)
	if d < 0 {
		d = 0
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
