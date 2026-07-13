package dhcpv6

import (
	"context"
	"testing"
	"time"
)

// TestLockWANMutualExclusion verifies that a second acquire on the same
// interface can't proceed while the first is held, but does once it's
// released -- the property that keeps two concurrent DHCPv6 exchanges from
// colliding on the same :546 bind.
func TestLockWANMutualExclusion(t *testing.T) {
	release, err := lockWAN(context.Background(), "wan-test-a")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// While held, an acquire with an already-expired deadline must fail
	// rather than proceed.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := lockWAN(ctx, "wan-test-a"); err == nil {
		t.Fatal("second acquire succeeded while the lock was held")
	}

	// After release, it's acquirable again.
	release()
	release2, err := lockWAN(context.Background(), "wan-test-a")
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	release2()
}

// TestLockWANPerInterface verifies the lock is keyed per interface: holding
// one interface's lock must not block another's.
func TestLockWANPerInterface(t *testing.T) {
	releaseA, err := lockWAN(context.Background(), "wan-test-b1")
	if err != nil {
		t.Fatalf("acquire b1: %v", err)
	}
	defer releaseA()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	releaseB, err := lockWAN(ctx, "wan-test-b2")
	if err != nil {
		t.Fatalf("acquire b2 blocked behind b1: %v", err)
	}
	releaseB()
}

// TestLockWANBlocksThenAcquiresOnRelease verifies a waiter blocked behind a
// held lock proceeds once the holder releases (not just when its ctx expires).
func TestLockWANBlocksThenAcquiresOnRelease(t *testing.T) {
	release, err := lockWAN(context.Background(), "wan-test-c")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	acquired := make(chan struct{})
	go func() {
		r, err := lockWAN(context.Background(), "wan-test-c")
		if err != nil {
			t.Errorf("blocked acquire: %v", err)
			return
		}
		close(acquired)
		r()
	}()

	// The waiter should still be blocked while the lock is held.
	select {
	case <-acquired:
		t.Fatal("acquired the lock while it was still held")
	case <-time.After(50 * time.Millisecond):
	}

	release()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("waiter did not acquire the lock after it was released")
	}
}
