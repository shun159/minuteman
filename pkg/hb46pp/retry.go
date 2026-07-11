package hb46pp

import (
	"errors"
	"math/rand/v2"
	"net"
	"time"
)

// The spec's retry backoff windows, by failure class (spec §3.4). Each
// is a uniformly random duration in its window, so a fleet of CPEs that
// failed together (e.g. against a briefly-down server) doesn't retry
// together.
const (
	// notProvisionedMin/Max: the TXT lookup answered NXDOMAIN/NODATA --
	// the VNE most likely doesn't offer HB46PP, so back off the
	// longest.
	notProvisionedMin = 1 * time.Hour
	notProvisionedMax = 3 * time.Hour

	// dnsFailureMin/Max: the TXT lookup failed for a transient reason
	// (timeout, unreachable resolver).
	dnsFailureMin = 1 * time.Minute
	dnsFailureMax = 10 * time.Minute

	// httpFailureMin/Max: the HTTP exchange or JSON validation failed.
	httpFailureMin = 10 * time.Minute
	httpFailureMax = 30 * time.Minute
)

// RetryDelay maps an error returned by Discover to the spec's backoff
// window for that failure class and returns a uniformly random delay
// within it. Discover is single-shot; callers that want the
// spec-compliant retry loop sleep for RetryDelay(err) between attempts.
func RetryDelay(err error) time.Duration {
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, ErrNotProvisioned):
		return randInterval(notProvisionedMin, notProvisionedMax)
	case errors.As(err, &dnsErr):
		return randInterval(dnsFailureMin, dnsFailureMax)
	default:
		return randInterval(httpFailureMin, httpFailureMax)
	}
}

// randInterval returns a uniformly random duration in [min, max] (same
// helper shape as pkg/routeradvert's).
func randInterval(min, max time.Duration) time.Duration {
	return min + time.Duration(rand.Float64()*float64(max-min))
}
