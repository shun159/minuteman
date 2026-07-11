package wanextend

import (
	"errors"
	"net/netip"
	"testing"
)

var (
	prefixA = netip.MustParsePrefix("2001:db8:1234:5678::/64")
	prefixB = netip.MustParsePrefix("2001:db8:aaaa:bbbb::/64")
)

func TestNextWatchStateUnchanged(t *testing.T) {
	updated, changed := nextWatchState(prefixA, prefixA, nil)
	if changed {
		t.Fatal("changed = true for an identical reading, want false")
	}
	if updated != prefixA {
		t.Fatalf("updated = %v, want unchanged %v", updated, prefixA)
	}
}

func TestNextWatchStateGenuineChange(t *testing.T) {
	updated, changed := nextWatchState(prefixA, prefixB, nil)
	if !changed {
		t.Fatal("changed = false for a genuinely different prefix, want true")
	}
	if updated != prefixB {
		t.Fatalf("updated = %v, want the new prefix %v", updated, prefixB)
	}
}

func TestNextWatchStateReadError(t *testing.T) {
	updated, changed := nextWatchState(prefixA, netip.Prefix{}, errors.New("netlink: boom"))
	if changed {
		t.Fatal("changed = true despite a read error, want false")
	}
	if updated != prefixA {
		t.Fatalf("updated = %v, want the retained current prefix %v", updated, prefixA)
	}
}

func TestNextWatchStateInvalidReading(t *testing.T) {
	// discoverPrefixOnce never returns (netip.Prefix{}, nil), but
	// nextWatchState guards against it anyway rather than trusting the
	// caller's contract.
	updated, changed := nextWatchState(prefixA, netip.Prefix{}, nil)
	if changed {
		t.Fatal("changed = true for an invalid (zero-value) reading, want false")
	}
	if updated != prefixA {
		t.Fatalf("updated = %v, want the retained current prefix %v", updated, prefixA)
	}
}

func TestNextWatchStateFirstPrefixIsAlwaysAChange(t *testing.T) {
	// A caller seeding current from netip.Prefix{} (no prior baseline)
	// should have any valid reading reported.
	updated, changed := nextWatchState(netip.Prefix{}, prefixA, nil)
	if !changed {
		t.Fatal("changed = false from a zero-value baseline, want true")
	}
	if updated != prefixA {
		t.Fatalf("updated = %v, want %v", updated, prefixA)
	}
}
