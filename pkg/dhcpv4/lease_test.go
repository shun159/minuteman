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
	other, _ := p.Offer("client-b", noIP, now)
	if other == first {
		t.Fatalf("two clients offered the same address %v", first)
	}
	again, _ := p.Offer("client-a", noIP, now.Add(time.Second))
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

func TestOfferedAddressIsReleasedAfterOfferHold(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	ip, _ := p.Offer("client-a", noIP, now)

	// Within the offer hold, the address is reserved: another client is
	// offered a different one.
	other, _ := p.Offer("client-b", noIP, now.Add(offerHoldTime/2))
	if other == ip {
		t.Fatalf("offered address %v handed to a second client before its offer expired", ip)
	}

	// After the (short) offer hold, an un-committed offer is reclaimed --
	// not held for the full lease.
	if free := p.isFree(ip, "client-c", now.Add(offerHoldTime+time.Second)); !free {
		t.Fatalf("offer for %v not reclaimed after offerHoldTime (%v)", ip, offerHoldTime)
	}
	if offerHoldTime >= p.duration {
		t.Fatalf("offerHoldTime %v should be much shorter than the lease %v", offerHoldTime, p.duration)
	}
}

func TestBindingReflectsOfferThenCommit(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	if _, ok := p.Binding("client-a", now); ok {
		t.Fatal("Binding for an unknown client should be false")
	}
	ip, _ := p.Offer("client-a", noIP, now)
	if b, ok := p.Binding("client-a", now); !ok || b != ip {
		t.Fatalf("Binding after Offer = %v/%v, want %v/true", b, ok, ip)
	}
	// A committed lease outlives the offer hold, an un-committed offer doesn't.
	p.Commit("client-a", ip, now)
	if b, ok := p.Binding("client-a", now.Add(offerHoldTime+time.Minute)); !ok || b != ip {
		t.Fatalf("Binding after Commit = %v/%v, want %v/true well past the offer hold", b, ok, ip)
	}
}

func TestCancelOfferReleasesOnlyUncommitted(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()

	// An offer can be cancelled (client selected another server).
	ip, _ := p.Offer("client-a", noIP, now)
	p.CancelOffer("client-a")
	if _, ok := p.Binding("client-a", now); ok {
		t.Fatal("CancelOffer left the offer in place")
	}
	if !p.isFree(ip, "client-b", now) {
		t.Fatal("cancelled offer's address is not free again")
	}

	// A committed lease must NOT be cancellable this way.
	ip2, _ := p.Offer("client-c", noIP, now)
	p.Commit("client-c", ip2, now)
	p.CancelOffer("client-c")
	if b, ok := p.Binding("client-c", now); !ok || b != ip2 {
		t.Fatal("CancelOffer wrongly dropped a committed lease")
	}
}

func TestExpiredCommittedLeaseIsReclaimed(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	ip, _ := p.Offer("client-a", noIP, now)
	p.Commit("client-a", ip, now)

	if p.isFree(ip, "client-b", now.Add(30*time.Minute)) {
		t.Fatal("an unexpired committed lease should not be free for another client")
	}
	if !p.isFree(ip, "client-b", now.Add(2*time.Hour)) {
		t.Fatal("an expired committed lease should be free for another client")
	}
}

func TestReleaseFreesAddress(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	ip, _ := p.Offer("client-a", noIP, now)
	p.Commit("client-a", ip, now)
	p.Release("client-a", ip)
	if !p.isFree(ip, "client-b", now) {
		t.Fatal("released address should be immediately reusable")
	}
}

func TestReleaseIgnoresWrongClient(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	ip, _ := p.Offer("client-a", noIP, now)
	p.Commit("client-a", ip, now)
	p.Release("client-b", ip) // not client-b's lease -> no-op
	if p.isFree(ip, "client-b", now) {
		t.Fatal("a client must not be able to release another client's lease")
	}
}

func TestDeclineOnlyQuarantinesOwnedAddress(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	ipA, _ := p.Offer("client-a", noIP, now)
	p.Commit("client-a", ipA, now)

	// client-b declines an address it doesn't hold (client-a's): must be
	// ignored -- no quarantine, client-a keeps its lease.
	p.Decline("client-b", ipA, now)
	if !p.allocatable(ipA, now) {
		t.Fatal("a client declining an address it doesn't hold quarantined it anyway (pool poisoning)")
	}
	if b, ok := p.Binding("client-a", now); !ok || b != ipA {
		t.Fatal("an unrelated decline dropped the real owner's lease")
	}

	// The real owner declining its own address quarantines it.
	p.Decline("client-a", ipA, now)
	if p.allocatable(ipA, now) {
		t.Fatal("a client's decline of its own address did not quarantine it")
	}
}

func TestDeclineQuarantineIsTimeBounded(t *testing.T) {
	p := newTestPool(t)
	now := time.Now()
	ip, _ := p.Offer("client-a", noIP, now)
	p.Commit("client-a", ip, now)
	p.Decline("client-a", ip, now)

	if p.allocatable(ip, now.Add(declineQuarantine/2)) {
		t.Fatal("declined address became allocatable before the quarantine elapsed")
	}
	if !p.allocatable(ip, now.Add(declineQuarantine+time.Second)) {
		t.Fatal("declined address never returned to the pool (permanent quarantine)")
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
