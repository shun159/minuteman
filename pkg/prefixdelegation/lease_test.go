package prefixdelegation

import (
	"net/netip"
	"testing"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
)

func TestLeaseShortestValidLifetime(t *testing.T) {
	lease := &Lease{
		Prefixes: []IAPrefix{
			{ValidLifetime: 7200 * time.Second, Prefix: netip.MustParsePrefix("2001:db8:1::/56")},
			{ValidLifetime: 3600 * time.Second, Prefix: netip.MustParsePrefix("2001:db8:2::/56")},
			{ValidLifetime: 5400 * time.Second, Prefix: netip.MustParsePrefix("2001:db8:3::/56")},
		},
	}
	if got, want := lease.shortestValidLifetime(), 3600*time.Second; got != want {
		t.Errorf("shortestValidLifetime() = %v, want %v", got, want)
	}
}

func TestLeaseIAPDOptionRoundTrip(t *testing.T) {
	lease := &Lease{
		Prefixes: []IAPrefix{
			{
				PreferredLifetime: 3600 * time.Second,
				ValidLifetime:     7200 * time.Second,
				Prefix:            netip.MustParsePrefix("2001:db8:1234:5600::/56"),
			},
		},
		T1: 1800 * time.Second,
		T2: 2880 * time.Second,
	}

	got, err := ParseIAPD(lease.iaPDOption())
	if err != nil {
		t.Fatalf("ParseIAPD: %v", err)
	}
	if got.IAID != clientIAID {
		t.Errorf("IAID = %v, want %v", got.IAID, clientIAID)
	}
	// RFC 9915 §21.21: a client zeroes T1/T2 in messages to the server.
	if got.T1 != 0 || got.T2 != 0 {
		t.Errorf("T1/T2 = %v/%v, want 0/0", got.T1, got.T2)
	}
	if len(got.Prefixes) != 1 || got.Prefixes[0].Prefix != lease.Prefixes[0].Prefix {
		t.Errorf("Prefixes = %v, want %v", got.Prefixes, lease.Prefixes)
	}
}

func TestNewLeaseResolvesTimers(t *testing.T) {
	serverID := dhcpv6.DUID{0x00, 0x03, 0xde, 0xad}
	// T1 = T2 = 0: the server delegates the renewal timing to us.
	lease := newLease(serverID, &IAPD{
		IAID:     clientIAID,
		Prefixes: []IAPrefix{prefixWithLifetimes(time.Hour, 2*time.Hour)},
	}, nil)

	if lease.T1 != 30*time.Minute || lease.T2 != 48*time.Minute {
		t.Errorf("T1/T2 = %v/%v, want 30m0s/48m0s", lease.T1, lease.T2)
	}
	if lease.AcquiredAt.IsZero() {
		t.Error("AcquiredAt is zero, want the time the lease was built")
	}
	if len(lease.Prefixes) != 1 {
		t.Fatalf("got %d prefixes, want 1", len(lease.Prefixes))
	}
}
