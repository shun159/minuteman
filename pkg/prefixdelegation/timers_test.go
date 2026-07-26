package prefixdelegation

import (
	"net/netip"
	"testing"
	"time"
)

func prefixWithLifetimes(preferred, valid time.Duration) IAPrefix {
	return IAPrefix{
		PreferredLifetime: preferred,
		ValidLifetime:     valid,
		Prefix:            netip.MustParsePrefix("2001:db8:1234:5600::/56"),
	}
}

func TestEffectiveTimers(t *testing.T) {
	const hour = time.Hour

	cases := []struct {
		name           string
		iapd           IAPD
		wantT1, wantT2 time.Duration
	}{
		{
			// RFC 9915 §21.21: non-zero values are a MUST-use.
			name:   "server sets both",
			iapd:   IAPD{T1: 1800 * time.Second, T2: 2880 * time.Second, Prefixes: []IAPrefix{prefixWithLifetimes(hour, 2*hour)}},
			wantT1: 1800 * time.Second,
			wantT2: 2880 * time.Second,
		},
		{
			// §14.2 + §21.21's recommended 0.5 x / 0.8 x ratios.
			name:   "both zero derives from shortest preferred lifetime",
			iapd:   IAPD{Prefixes: []IAPrefix{prefixWithLifetimes(hour, 2*hour)}},
			wantT1: 30 * time.Minute,
			wantT2: 48 * time.Minute,
		},
		{
			name: "both zero uses the shortest preferred lifetime of several prefixes",
			iapd: IAPD{Prefixes: []IAPrefix{
				prefixWithLifetimes(4*hour, 8*hour),
				prefixWithLifetimes(hour, 2*hour),
				prefixWithLifetimes(2*hour, 4*hour),
			}},
			wantT1: 30 * time.Minute,
			wantT2: 48 * time.Minute,
		},
		{
			// 0.5 x 40s would be 20s, so the floor takes over at 60s;
			// T2 would then be pushed to 90s, past the point the binding
			// dies, so the valid lifetime caps it instead.
			name:   "both zero with a short lifetime is floored, ordered and capped at the valid lifetime",
			iapd:   IAPD{Prefixes: []IAPrefix{prefixWithLifetimes(40*time.Second, 80*time.Second)}},
			wantT1: minDerivedT1,
			wantT2: 80 * time.Second,
		},
		{
			// Lifetimes so short that even the floor lands after the
			// binding is gone: renewing at the floor would only ever
			// fail into a full re-Acquire, so the lease's own life wins.
			name:   "both zero with a lifetime shorter than the floor renews inside it",
			iapd:   IAPD{Prefixes: []IAPrefix{prefixWithLifetimes(10*time.Second, 20*time.Second)}},
			wantT1: 10 * time.Second,
			wantT2: 15 * time.Second,
		},
		{
			// The cap follows the shortest valid lifetime, like the
			// ratios follow the shortest preferred one.
			name: "both zero caps at the shortest valid lifetime of several prefixes",
			iapd: IAPD{Prefixes: []IAPrefix{
				prefixWithLifetimes(40*time.Second, 300*time.Second),
				prefixWithLifetimes(40*time.Second, 70*time.Second),
			}},
			wantT1: minDerivedT1,
			wantT2: 70 * time.Second,
		},
		{
			name:   "zero T1 alone derives from the preferred lifetime",
			iapd:   IAPD{T2: 48 * time.Minute, Prefixes: []IAPrefix{prefixWithLifetimes(hour, 2*hour)}},
			wantT1: 30 * time.Minute,
			wantT2: 48 * time.Minute,
		},
		{
			// The server's T2 is sooner than 0.5 x preferred: Renew is
			// only valid until T2, so T1 must stay inside that window.
			name:   "zero T1 stays inside a server T2 that comes sooner",
			iapd:   IAPD{T2: 20 * time.Minute, Prefixes: []IAPrefix{prefixWithLifetimes(hour, 2*hour)}},
			wantT1: 10 * time.Minute,
			wantT2: 20 * time.Minute,
		},
		{
			name:   "zero T2 alone derives from the preferred lifetime",
			iapd:   IAPD{T1: 30 * time.Minute, Prefixes: []IAPrefix{prefixWithLifetimes(hour, 2*hour)}},
			wantT1: 30 * time.Minute,
			wantT2: 48 * time.Minute,
		},
		{
			// 0.8 x preferred (48m) lands before the server's own T1, so
			// T2 is pushed past it instead of inverting the ladder.
			name:   "zero T2 is pushed past a server T1 beyond the ratio",
			iapd:   IAPD{T1: 50 * time.Minute, Prefixes: []IAPrefix{prefixWithLifetimes(hour, 2*hour)}},
			wantT1: 50 * time.Minute,
			wantT2: 75 * time.Minute,
		},
		{
			// §7.7 / §21.4: an infinite lifetime is a permanent
			// delegation, and is never renewed.
			name:   "infinite preferred lifetime gives infinite timers",
			iapd:   IAPD{Prefixes: []IAPrefix{prefixWithLifetimes(infiniteLifetime, infiniteLifetime)}},
			wantT1: infiniteLifetime,
			wantT2: infiniteLifetime,
		},
		{
			name:   "prefix-less IA_PD still yields usable timers",
			iapd:   IAPD{},
			wantT1: minDerivedT1,
			wantT2: minDerivedT1 + minDerivedT1/2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotT1, gotT2 := effectiveTimers(&c.iapd)
			if gotT1 != c.wantT1 || gotT2 != c.wantT2 {
				t.Errorf("effectiveTimers() = %v/%v, want %v/%v", gotT1, gotT2, c.wantT1, c.wantT2)
			}
		})
	}
}

// TestEffectiveTimersNeverImmediateOrInverted covers RFC 9915 §14.2's two
// hard requirements over a spread of server inputs -- the client never
// transmits immediately (T1 > 0), and the Renew-then-Rebind ladder stays
// ordered so Maintain's renew deadline (T2) is always after its renew
// time (T1) -- plus the ceiling that keeps a derived timer inside the
// binding's own life.
func TestEffectiveTimersNeverImmediateOrInverted(t *testing.T) {
	lifetimes := []time.Duration{0, time.Second, 30 * time.Second, time.Hour, 24 * time.Hour, infiniteLifetime}
	timers := []time.Duration{0, time.Second, time.Minute, time.Hour, 24 * time.Hour}

	for _, preferred := range lifetimes {
		for _, t1 := range timers {
			for _, t2 := range timers {
				if t2 > 0 && t1 > t2 {
					continue // discarded by usableIAPD before it gets here
				}
				iapd := IAPD{T1: t1, T2: t2, Prefixes: []IAPrefix{prefixWithLifetimes(preferred, preferred)}}
				gotT1, gotT2 := effectiveTimers(&iapd)
				if gotT1 <= 0 {
					t.Errorf("T1/T2 %v/%v, preferred %v: got T1 %v, want > 0", t1, t2, preferred, gotT1)
				}
				if gotT2 < gotT1 {
					t.Errorf("T1/T2 %v/%v, preferred %v: got %v/%v, want T2 >= T1", t1, t2, preferred, gotT1, gotT2)
				}
				// The prefixes here have valid == preferred, so a
				// derived timer that outruns it would schedule work
				// against a binding that no longer exists. (Only when
				// the lifetime leaves room for it: a server-pinned T1
				// already past the lifetime is the server's business.)
				if preferred > 0 && preferred != infiniteLifetime && gotT1 < preferred && gotT2 > preferred {
					if t2 == 0 {
						t.Errorf("T1/T2 %v/%v, preferred %v: got T2 %v, want <= the %v valid lifetime", t1, t2, preferred, gotT2, preferred)
					}
				}
			}
		}
	}
}

func TestShortestPreferredLifetime(t *testing.T) {
	prefixes := []IAPrefix{
		prefixWithLifetimes(2*time.Hour, 4*time.Hour),
		prefixWithLifetimes(time.Hour, 2*time.Hour),
		prefixWithLifetimes(3*time.Hour, 6*time.Hour),
	}
	if got, want := shortestPreferredLifetime(prefixes), time.Hour; got != want {
		t.Errorf("shortestPreferredLifetime() = %v, want %v", got, want)
	}
	if got := shortestPreferredLifetime(nil); got != 0 {
		t.Errorf("shortestPreferredLifetime(nil) = %v, want 0", got)
	}
}
