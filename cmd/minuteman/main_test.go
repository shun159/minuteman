package main

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/shun159/miniteman/pkg/aftrdiscovery"
	"github.com/shun159/miniteman/pkg/hb46pp"
	"github.com/shun159/miniteman/pkg/prefixdelegation"
)

func TestNextB4(t *testing.T) {
	a := netip.MustParseAddr("2001:db8::1")
	b := netip.MustParseAddr("2001:db8::2")

	tests := []struct {
		name        string
		current     netip.Addr
		queried     netip.Addr
		ok          bool
		wantB4      netip.Addr
		wantChanged bool
	}{
		{
			name:        "genuine change",
			current:     a,
			queried:     b,
			ok:          true,
			wantB4:      b,
			wantChanged: true,
		},
		{
			name:        "same address is not a change",
			current:     a,
			queried:     a,
			ok:          true,
			wantB4:      a,
			wantChanged: false,
		},
		{
			// A momentarily-absent source (ok=false, e.g. mid-renumbering or a
			// netlink error) must keep the current B4, never switch to invalid.
			name:        "no source keeps current, even with a stale queried value",
			current:     a,
			queried:     b,
			ok:          false,
			wantB4:      a,
			wantChanged: false,
		},
		{
			name:        "invalid queried address keeps current",
			current:     a,
			queried:     netip.Addr{},
			ok:          true,
			wantB4:      a,
			wantChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotB4, gotChanged := nextB4(tt.current, tt.queried, tt.ok)
			if gotB4 != tt.wantB4 || gotChanged != tt.wantChanged {
				t.Errorf("nextB4(%v, %v, %v) = (%v, %v), want (%v, %v)",
					tt.current, tt.queried, tt.ok, gotB4, gotChanged, tt.wantB4, tt.wantChanged)
			}
		})
	}
}

func TestRetryDelayForCapsNoReply(t *testing.T) {
	// ErrNotProvisioned alone earns hb46pp's longest backoff (1-3h). Reached
	// via an unanswered Information-Request, that verdict rests on nothing
	// DHCPv6 told us, so retryDelayFor caps it.
	bare := fmt.Errorf("HB46PP: %w", hb46pp.ErrNotProvisioned)
	if got := retryDelayFor(bare); got <= noReplyRetryCap {
		t.Fatalf("retryDelayFor(ErrNotProvisioned) = %v, want the full backoff (> %v)", got, noReplyRetryCap)
	}

	viaNoReply := fmt.Errorf("%w (reached because %w)", bare, aftrdiscovery.ErrNoReply)
	if got := retryDelayFor(viaNoReply); got != noReplyRetryCap {
		t.Errorf("retryDelayFor(... ErrNoReply) = %v, want %v", got, noReplyRetryCap)
	}
}

func TestRetryDelayForKeepsShorterDelays(t *testing.T) {
	// A delay already below the cap is left alone rather than raised to it.
	dnsErr := fmt.Errorf("%w: %w", aftrdiscovery.ErrNoReply, &net.DNSError{Err: "timeout", IsTimeout: true})
	got := retryDelayFor(dnsErr)
	if got > noReplyRetryCap {
		t.Errorf("retryDelayFor(DNS failure) = %v, want <= %v", got, noReplyRetryCap)
	}
}

func TestPDDNSServers(t *testing.T) {
	if got := pdDNSServers(nil); got != nil {
		t.Errorf("pdDNSServers(nil) = %v, want nil", got)
	}
	srv := []netip.Addr{netip.MustParseAddr("2001:db8::53")}
	if got := pdDNSServers(&prefixdelegation.Lease{DNSServers: srv}); len(got) != 1 || got[0] != srv[0] {
		t.Errorf("pdDNSServers() = %v, want %v", got, srv)
	}
}
