package softwirectl

import (
	"context"
	"time"

	"github.com/shun159/molecule"
)

// rediscoveryTimeout bounds one re-discovery attempt. Unlike the initial
// discovery (which blocks until it succeeds -- no AFTR, no service), a
// re-discovery is best-effort: the current AFTR still works, so if an attempt
// can't finish promptly it's abandoned and retried next interval. Bounding it
// also bounds how long it holds the WAN's DHCPv6 client, which runs one
// exchange at a time (internal/dhcpv6client), so a stuck Information-Request
// can't starve DHCPv6-PD renewal.
const rediscoveryTimeout = 2 * time.Minute

// DiscoverFunc runs one AFTR discovery attempt, echoing token on an HB46PP
// request.
type DiscoverFunc func(ctx context.Context, token string) (Discovery, error)

// discoverKey is the key of the discovery attempt running, an Async.
type discoverKey struct{}

// discoverRep is the outcome of a discovery attempt.
type discoverRep struct {
	Disc    Discovery
	Err     error
	RetryIn time.Duration // after a failure, the backoff for its class
}

// discover is the Async running one discovery attempt, echoing token. It
// blocks for up to rediscoveryTimeout, which a callback must not, and the
// controller must be able to abandon it on a WAN-address change
// (CancelAsync). The backoff after a failure is random, so it is drawn here
// too, and the controller stays deterministic.
func (c Controller) discover(token string) molecule.Effect {
	return molecule.Async{Key: discoverKey{}, Run: func(ctx context.Context) (any, error) {
		ctx, cancel := context.WithTimeout(ctx, rediscoveryTimeout)
		defer cancel()
		disc, err := c.Discover(ctx, token)
		rep := discoverRep{Disc: disc, Err: err}
		if err != nil {
			rep.RetryIn = c.RetryDelay(err)
		}
		return rep, nil
	}}
}
