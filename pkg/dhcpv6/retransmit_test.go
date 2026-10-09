package dhcpv6

import (
	"math/rand/v2"
	"testing"
	"time"
)

var rng = rand.New(rand.NewPCG(1, 2))

func TestRandDelayBounds(t *testing.T) {
	for _, max := range []time.Duration{0, InfMaxDelay, SolMaxDelay} {
		t.Run(max.String(), func(t *testing.T) {
			for i := 0; i < 1000; i++ {
				d := InitialDelay(max, rng)
				if d < 0 || d > max {
					t.Fatalf("InitialDelay(%v) = %v, want in [0, %v]", max, d, max)
				}
			}
		})
	}
	if d := InitialDelay(0, rng); d != 0 {
		t.Fatalf("InitialDelay(0, rng) = %v, want exactly 0", d)
	}
}

func TestFirstRTBounds(t *testing.T) {
	for _, irt := range []time.Duration{InfTimeout, SolTimeout, ReqTimeout, RenTimeout, RebTimeout, RelTimeout} {
		t.Run(irt.String(), func(t *testing.T) {
			lo := time.Duration(0.9 * float64(irt))
			hi := time.Duration(1.1 * float64(irt))
			for i := 0; i < 1000; i++ {
				rt := FirstRT(irt, rng)
				if rt < lo || rt > hi {
					t.Fatalf("FirstRT(%v) = %v, want in [%v, %v]", irt, rt, lo, hi)
				}
			}
		})
	}
}

func TestNextRTBelowCapRoughlyDoubles(t *testing.T) {
	for _, mrt := range []time.Duration{InfMaxRT, SolMaxRT, ReqMaxRT, RenMaxRT, RebMaxRT} {
		t.Run(mrt.String(), func(t *testing.T) {
			prev := 1 * time.Second // far below every mrt above, so the cap never engages here
			lo := time.Duration(0.9 * float64(2*prev))
			hi := time.Duration(1.1 * float64(2*prev))
			for i := 0; i < 1000; i++ {
				rt := NextRT(prev, mrt, rng)
				if rt < lo || rt > hi {
					t.Fatalf("NextRT(%v, %v) = %v, want in [%v, %v]", prev, mrt, rt, lo, hi)
				}
			}
		})
	}
}

// TestNextRTAtCapKeepsJittering is the regression test for the bug an
// earlier min()-based formulation had: once RT reaches the MRT ceiling, it
// must keep varying +/-10% around MRT on every subsequent call, not
// collapse to a single fixed value.
func TestNextRTAtCapKeepsJittering(t *testing.T) {
	mrt := 100 * time.Second
	lo := time.Duration(0.9 * float64(mrt))
	hi := time.Duration(1.1 * float64(mrt))

	seen := map[time.Duration]bool{}
	prev := mrt
	for i := 0; i < 1000; i++ {
		prev = NextRT(prev, mrt, rng)
		if prev < lo || prev > hi {
			t.Fatalf("NextRT at cap = %v, want in [%v, %v]", prev, lo, hi)
		}
		seen[prev] = true
	}
	if len(seen) < 2 {
		t.Fatalf("NextRT at cap produced only %d distinct value(s) over 1000 calls; jitter appears lost", len(seen))
	}
}

func TestNextRTZeroMRTNeverCaps(t *testing.T) {
	prev := 10 * time.Hour
	rt := NextRT(prev, 0, rng)
	// mrt=0 means "no ceiling" (RFC 3315 SS14); the doubled value should
	// pass through uncapped.
	lo := time.Duration(0.9 * float64(2*prev))
	if rt < lo {
		t.Fatalf("NextRT(%v, 0, rng) = %v, want roughly 2x prev uncapped", prev, rt)
	}
}
