package prefixdelegation

import (
	"net/netip"
	"testing"
	"time"
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
	if got.T1 != lease.T1 || got.T2 != lease.T2 {
		t.Errorf("T1/T2 = %v/%v, want %v/%v", got.T1, got.T2, lease.T1, lease.T2)
	}
	if len(got.Prefixes) != 1 || got.Prefixes[0].Prefix != lease.Prefixes[0].Prefix {
		t.Errorf("Prefixes = %v, want %v", got.Prefixes, lease.Prefixes)
	}
}
