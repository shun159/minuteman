package routeradvert

import (
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNextUnsolicitedInterval(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for sent := range 10 {
		lo, hi := time.Duration(0), maxInitialRtrAdvertInterval
		if sent >= maxInitialRtrAdvertisements {
			lo, hi = minRtrAdvInterval, maxRtrAdvInterval
		}
		for range 100 {
			if d := NextUnsolicitedInterval(sent, r); d < lo || d > hi {
				t.Fatalf("NextUnsolicitedInterval(%d) = %v, want in [%v, %v]", sent, d, lo, hi)
			}
		}
	}
}

func TestReplyDelay(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 100 {
		if d := ReplyDelay(r); d < 0 || d > maxRADelayTime {
			t.Fatalf("ReplyDelay = %v", d)
		}
	}
}

// The RDNSS server is withdrawn with the router: its lifetime is the RA's.
func TestBuildRA(t *testing.T) {
	cfg := Config{
		Prefix:            netip.MustParsePrefix("2001:db8:1::/64"),
		OnLink:            true,
		ValidLifetime:     time.Hour,
		PreferredLifetime: 30 * time.Minute,
		RDNSSAddr:         netip.MustParseAddr("fe80::1"),
	}
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	for _, lifetime := range []time.Duration{AdvDefaultLifetime, 0} {
		ra := BuildRA(cfg, lifetime, mac)
		if ra.RouterLifetime != lifetime || len(ra.Options) != 3 {
			t.Errorf("RA with lifetime %v: %+v", lifetime, ra)
		}
	}
	cfg.RDNSSAddr = netip.Addr{}
	if ra := BuildRA(cfg, AdvDefaultLifetime, mac); len(ra.Options) != 2 {
		t.Errorf("RA without RDNSS carries %d options", len(ra.Options))
	}
}
