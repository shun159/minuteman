package routeradvert

import (
	"net/netip"
	"testing"
	"time"
)

// Serve itself needs a raw ICMPv6 socket, so only Updater's queueing
// behaviour is unit-tested here -- the rest of this file's logic is
// exercised by test/netns, like the package's other socket-bound code.

func testConfig(preferred time.Duration) Config {
	return Config{
		Prefix:            netip.MustParsePrefix("2001:db8:1::/64"),
		OnLink:            true,
		ValidLifetime:     2 * preferred,
		PreferredLifetime: preferred,
	}
}

func TestUpdaterSetDoesNotBlock(t *testing.T) {
	u := NewUpdater()

	// More Sets than the channel can hold: each must return rather than
	// wait for a Serve that may not be reading yet (a worker still in its
	// socket setup, or one that has already exited).
	for i := range 5 {
		done := make(chan struct{})
		go func() {
			defer close(done)
			u.Set(testConfig(time.Duration(i) * time.Second))
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("Set #%d blocked", i)
		}
	}
}

func TestUpdaterSetKeepsLatest(t *testing.T) {
	u := NewUpdater()

	u.Set(testConfig(time.Second))
	u.Set(testConfig(2 * time.Second))
	want := testConfig(3 * time.Second)
	u.Set(want)

	select {
	case got := <-u.ch:
		if got != want {
			t.Fatalf("got %+v, want the most recent Set %+v", got, want)
		}
	default:
		t.Fatal("no update queued")
	}

	select {
	case got := <-u.ch:
		t.Fatalf("superseded updates were queued too: got %+v", got)
	default:
	}
}
