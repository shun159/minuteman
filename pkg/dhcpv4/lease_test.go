package dhcpv4

import (
	"net/netip"
	"testing"
	"time"
)

func newTestPool(t *testing.T) *Pool {
	t.Helper()
	p, err := NewPool(netip.MustParsePrefix("192.168.1.0/24"), netip.MustParseAddr("192.168.1.1"), time.Hour)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	return p
}

var noIP = netip.Addr{}

func TestOfferSkipsReservedAddresses(t *testing.T) {
	p := newTestPool(t)
	ip, ok := p.Offer("client-a", noIP, time.Now())
	if !ok {
		t.Fatal("Offer: pool unexpectedly exhausted")
	}
	// .0 (network), .1 (server), .255 (broadcast) must never be offered;
	// the lowest free is .2.
	if ip != netip.MustParseAddr("192.168.1.2") {
		t.Fatalf("Offer = %v, want 192.168.1.2 (lowest non-reserved)", ip)
	}
}

func TestOfferIsStickyPerClient(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	first, _ := p.Offer("client-a", noIP, now)
	// A different client is offered a different address...
	other, _ := p.Offer("client-b", noIP, now)
	if other == first {
		t.Fatalf("two clients offered the same address %v", first)
	}
	// ...and the first client, re-DISCOVERing, gets its original address back.
	again, _ := p.Offer("client-a", noIP, now.Add(time.Minute))
	if again != first {
		t.Fatalf("re-Offer = %v, want the original %v", again, first)
	}
}

func TestOfferHonoursFreeRequestedAddress(t *testing.T) {
	p := newTestPool(t)
	want := netip.MustParseAddr("192.168.1.50")
	ip, ok := p.Offer("client-a", want, time.Now())
	if !ok || ip != want {
		t.Fatalf("Offer with requested %v = %v/%v", want, ip, ok)
	}
}

func TestCommitFreeAddressSucceeds(t *testing.T) {
	p := newTestPool(t)
	want := netip.MustParseAddr("192.168.1.77")
	ip, ok := p.Commit("client-a", want, time.Now())
	if !ok || ip != want {
		t.Fatalf("Commit = %v/%v, want %v/true (post-restart recovery)", ip, ok, want)
	}
}

func TestCommitAddressHeldByAnotherClientNAKs(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	ip, _ := p.Offer("client-a", noIP, now)
	if _, ok := p.Commit("client-b", ip, now); ok {
		t.Fatalf("Commit of client-a's address by client-b: want NAK (ok=false)")
	}
}

func TestCommitRejectsReservedAndOutOfSubnet(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	for _, bad := range []string{"192.168.1.1", "192.168.1.0", "192.168.1.255", "10.0.0.5"} {
		if _, ok := p.Commit("c", netip.MustParseAddr(bad), now); ok {
			t.Errorf("Commit(%s): want NAK (ok=false)", bad)
		}
	}
}

func TestExpiredLeaseIsReclaimed(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	ip, _ := p.Offer("client-a", noIP, now)

	// Before expiry, another client can't take it.
	if _, ok := p.Commit("client-b", ip, now.Add(30*time.Minute)); ok {
		t.Fatal("Commit of an unexpired lease by another client should NAK")
	}
	// After expiry, it's free for someone else.
	if _, ok := p.Commit("client-b", ip, now.Add(2*time.Hour)); !ok {
		t.Fatal("Commit of an expired lease by another client should succeed")
	}
}

func TestReleaseFreesAddress(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	ip, _ := p.Offer("client-a", noIP, now)
	p.Release("client-a", ip)
	if _, ok := p.Commit("client-b", ip, now); !ok {
		t.Fatal("released address should be immediately reusable")
	}
}

func TestReleaseIgnoresWrongClient(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	ip, _ := p.Offer("client-a", noIP, now)
	p.Release("client-b", ip) // not client-b's lease -> no-op
	if _, ok := p.Commit("client-b", ip, now); ok {
		t.Fatal("a client must not be able to release another client's lease")
	}
}

func TestDeclinedAddressIsNeverReoffered(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	ip, _ := p.Offer("client-a", noIP, now)
	p.Decline("client-a", ip)

	// It must not come back, even to the same client, and even much later.
	for i := range 300 {
		next, ok := p.Offer("client-a", noIP, now.Add(time.Duration(i)*time.Hour))
		if !ok {
			break
		}
		if next == ip {
			t.Fatalf("declined address %v was offered again", ip)
		}
	}
}

func TestPoolExhaustion(t *testing.T) {
	// A /30 has exactly one usable host address once network, broadcast, and
	// the server are excluded.
	p, err := NewPool(netip.MustParsePrefix("192.168.1.0/30"), netip.MustParseAddr("192.168.1.1"), time.Hour)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	now := time.Now()
	if ip, ok := p.Offer("client-a", noIP, now); !ok || ip != netip.MustParseAddr("192.168.1.2") {
		t.Fatalf("first Offer = %v/%v, want 192.168.1.2/true", ip, ok)
	}
	if _, ok := p.Offer("client-b", noIP, now); ok {
		t.Fatal("second Offer should fail: /30 pool has only one host address")
	}
}

func TestNewPoolValidation(t *testing.T) {
	cases := []struct {
		subnet, server string
	}{
		{"192.168.1.0/31", "192.168.1.0"}, // no host range
		{"192.168.1.0/24", "10.0.0.1"},    // server outside subnet
		{"2001:db8::/64", "2001:db8::1"},  // not IPv4
	}
	for _, c := range cases {
		if _, err := NewPool(netip.MustParsePrefix(c.subnet), netip.MustParseAddr(c.server), time.Hour); err == nil {
			t.Errorf("NewPool(%s, %s): want error, got nil", c.subnet, c.server)
		}
	}
}
