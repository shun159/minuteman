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
