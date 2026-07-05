package dhcpv6

import (
	"math/rand/v2"
	"time"
)

// Retransmission constants for Information-Request (RFC 3315 §18.1.5): the
// initial delay before the first transmission, the initial retransmission
// timeout, and the retransmission timeout ceiling. Information-Request has
// no maximum retransmission count or duration (RFC 3315 §18.1.5: both are
// 0, i.e. unbounded) -- retries continue, capped at InfMaxRT, until the
// caller's context is cancelled.
const (
	InfMaxDelay = 1 * time.Second
	InfTimeout  = 1 * time.Second
	InfMaxRT    = 3600 * time.Second
)

// Retransmission constants for the remaining RFC 3315 §5.5 exchanges a
// stateful (e.g. prefix delegation) client drives. Solicit has an initial
// delay and no maximum retransmission count, exactly like
// Information-Request above (retries forever, capped at SolMaxRT, until the
// context is cancelled or a usable Advertise arrives). Request/Renew/Rebind/
// Release send immediately (no initial delay per RFC 3315 §18.1.1/§18.1.3/
// §18.1.4/§18.1.6). Request and Release additionally have a maximum
// retransmission *count* (MRC): once exhausted, the exchange gives up
// instead of retrying forever -- RFC 3315 §18.1.1 says a client whose
// Request goes unanswered should restart at Solicit, and §18.1.6 says a
// client should stop using a released binding locally regardless of whether
// Release was ever acknowledged. Renew/Rebind have no MRC either, but are
// still bounded in practice: the caller wraps ctx with a deadline (T2, or
// the shortest remaining valid lifetime, respectively) rather than this
// package tracking lease timing itself.
const (
	SolMaxDelay = 1 * time.Second
	SolTimeout  = 1 * time.Second
	SolMaxRT    = 3600 * time.Second

	ReqTimeout = 1 * time.Second
	ReqMaxRT   = 30 * time.Second
	ReqMaxRC   = 10

	RenTimeout = 10 * time.Second
	RenMaxRT   = 600 * time.Second

	RebTimeout = 10 * time.Second
	RebMaxRT   = 600 * time.Second

	RelTimeout = 1 * time.Second
	RelMaxRC   = 5
)

// jitter returns a uniformly random value in [-0.1, 0.1] * base, the RAND
// factor from RFC 3315 §14.
func jitter(base time.Duration) time.Duration {
	return time.Duration((rand.Float64()*0.2 - 0.1) * float64(base))
}

// randDelay returns a uniformly random delay in [0, max], applied before the
// very first transmission of a message exchange (RFC 3315 §14/§18.1.5/
// §17.1.2) to avoid clients synchronizing retransmissions after a shared
// event (e.g. many CPEs rebooting together after a power outage). Exchanges
// that RFC 3315 says send immediately (Request, Renew, Rebind, Release) pass
// max=0, for which randDelay always returns 0 without calling rand.
func randDelay(max time.Duration) time.Duration {
	if max == 0 {
		return 0
	}
	return time.Duration(rand.Float64() * float64(max))
}

// firstRT returns the first retransmission timeout: RT = IRT + RAND*IRT
// (RFC 3315 §14).
func firstRT(irt time.Duration) time.Duration {
	return irt + jitter(irt)
}

// nextRT computes the next retransmission timeout from the previous one
// (RFC 3315 §14):
//
//	RT = 2*RTprev + RAND*RTprev
//	if MRT != 0 and RT > MRT:
//	    RT = MRT + RAND*MRT
//
// The second step re-applies jitter around the MRT ceiling itself, rather
// than clamping to a fixed MRT -- so once steady state is reached (e.g.
// hour-long retries against InfMaxRT), retransmissions keep varying ±10%
// around the ceiling indefinitely instead of converging to a single fixed
// interval, preserving RAND's anti-synchronization purpose for exactly the
// long-running case where it matters most.
func nextRT(prev, mrt time.Duration) time.Duration {
	rt := 2*prev + jitter(prev)
	if mrt != 0 && rt > mrt {
		rt = mrt + jitter(mrt)
	}
	return rt
}
