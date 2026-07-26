package prefixdelegation

import (
	"math"
	"time"
)

// infiniteLifetime is the 0xffffffff ("infinity") lifetime of RFC 9915
// §7.7, in the time.Duration form ParseIAPD produces for such a field.
const infiniteLifetime = time.Duration(math.MaxUint32) * time.Second

// minDerivedT1 is the floor on a T1 this package picks for itself. RFC
// 9915 §14.2 only says a client left to choose its own renewal times MUST
// avoid message storms and MUST NOT transmit immediately; §14.1 is what
// puts a number on "storm" (a client MUST rate-limit its transmissions,
// with a suggested default of 20 messages in 20 seconds). A minute
// between renewal exchanges stays far below that and is still far more
// often than any real delegation needs. It bounds only the values derived
// here -- a non-zero T1 from the server is used as-is however small,
// since §21.21 makes that a MUST.
const minDerivedT1 = time.Minute

// effectiveTimers returns the T1/T2 renewal timers a lease should
// actually run on, given what the delegating server sent in iapd.
//
// A server sends T1 and/or T2 as 0 to leave that timer to the requesting
// router's discretion (RFC 9915 §21.21). Taken literally, 0 means "renew
// immediately, forever" -- which is why §14.2 bounds that discretion: the
// client MUST choose a time that avoids message storms, and in particular
// MUST NOT transmit immediately. The values chosen here are §21.21's own
// recommended ones -- 0.5 and 0.8 times the shortest preferred lifetime
// of the delegated prefixes, the ratios that section recommends to a
// server picking T1/T2 -- floored by minDerivedT1 and kept ordered
// T1 <= T2 so Maintain's Renew-then-Rebind ladder stays meaningful.
//
// Both derived values are additionally kept inside the lease's own life:
// the binding is gone at the shortest valid lifetime, and a Renew
// scheduled past that point can only fail into a full re-Acquire -- more
// messages than renewing in time, not fewer, so the ceiling serves the
// same anti-storm purpose the floor does.
//
// A non-zero value from the server is never second-guessed: §21.21 says
// the client MUST use it. usableIAPD has already discarded the one
// non-zero combination §21.21 calls invalid (T1 > T2 > 0).
func effectiveTimers(iapd *IAPD) (t1, t2 time.Duration) {
	t1, t2 = iapd.T1, iapd.T2
	if t1 > 0 && t2 > 0 {
		return t1, t2
	}
	recT1, recT2 := recommendedTimers(shortestPreferredLifetime(iapd.Prefixes))
	valid := shortestValidLifetime(iapd.Prefixes)

	if t1 == 0 {
		t1 = recT1
		if t1 < minDerivedT1 {
			t1 = minDerivedT1
		}
		// Two deadlines the floor above must not push T1 past: the
		// server's own T2, if it pinned one (Renew is only valid until
		// T2, §18.2.4), and the lease's own death. Whichever applies,
		// the resulting cadence follows from the server's own numbers,
		// which is why the floor deliberately doesn't apply to it.
		if limit := earlier(t2, valid); limit > 0 && limit != infiniteLifetime && t1 >= limit {
			t1 = limit / 2
		}
	}
	if t2 == 0 {
		switch {
		case t1 == infiniteLifetime:
			// Never renewing means never rebinding either.
			t2 = infiniteLifetime
		case recT2 > t1:
			t2 = recT2
		default:
			// Either the T1 floor above outran 0.8 x preferred, or the
			// server pinned a T1 past it. Rebind has to come after
			// Renew, so put T2 half a T1 beyond it.
			t2 = t1 + t1/2
		}
		if valid > t1 && t2 > valid {
			// Renewing beyond the binding's own valid lifetime is
			// pointless -- that instant is where Maintain gives up on it
			// anyway (tryRebind's deadline) -- so stop the Renew stage
			// there. Guarded on valid > t1 so a server T1 already past
			// the lifetime can't invert the ladder.
			t2 = valid
		}
	}
	return t1, t2
}

// earlier returns whichever of a and b comes first, ignoring a zero
// (meaning "no such deadline") on either side; zero if both are zero.
func earlier(a, b time.Duration) time.Duration {
	if a == 0 || (b > 0 && b < a) {
		return b
	}
	return a
}

// recommendedTimers returns RFC 9915 §21.21's recommended T1/T2 for a
// shortest preferred lifetime of preferred: 0.5 and 0.8 times it, or
// infinity for both when the lifetime is itself infinite -- §21.4 spells
// that case out for IA_NA, and §7.7's "infinity amounts to a permanent
// assignment" makes it read identically for a delegated prefix: there is
// nothing to renew.
func recommendedTimers(preferred time.Duration) (t1, t2 time.Duration) {
	if preferred == infiniteLifetime {
		return infiniteLifetime, infiniteLifetime
	}
	// Divide before multiplying for T2: the product would overflow a
	// time.Duration for a near-infinite preferred lifetime, and the few
	// nanoseconds the division order costs are immaterial.
	return preferred / 2, preferred / 5 * 4
}

// shortestPreferredLifetime returns the smallest PreferredLifetime across
// prefixes -- the quantity RFC 9915 §21.21's recommended T1/T2 ratios are
// taken from.
//
// Returns 0 for an empty list, which effectiveTimers turns into its floor
// (and, for shortestValidLifetime, into "no such deadline"); usableIAPD
// rejects a prefix-less IA_PD before either is reached.
func shortestPreferredLifetime(prefixes []IAPrefix) time.Duration {
	if len(prefixes) == 0 {
		return 0
	}
	shortest := prefixes[0].PreferredLifetime
	for _, p := range prefixes[1:] {
		if p.PreferredLifetime < shortest {
			shortest = p.PreferredLifetime
		}
	}
	return shortest
}

// shortestValidLifetime returns the smallest ValidLifetime across
// prefixes -- the point by which RFC 3315 §18.1.4 says a client must stop
// using a binding if Rebind hasn't succeeded by then, and so the ceiling
// on any timer effectiveTimers picks. Lease.shortestValidLifetime is the
// same question asked of an established lease.
func shortestValidLifetime(prefixes []IAPrefix) time.Duration {
	if len(prefixes) == 0 {
		return 0
	}
	shortest := prefixes[0].ValidLifetime
	for _, p := range prefixes[1:] {
		if p.ValidLifetime < shortest {
			shortest = p.ValidLifetime
		}
	}
	return shortest
}
