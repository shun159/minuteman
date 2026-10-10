package routeradvert

import (
	"math/rand/v2"
	"net"
	"net/netip"
	"time"
)

// RFC 4861 §6.2.1 default Router Configuration Variables.
const (
	maxRtrAdvInterval  = 600 * time.Second
	minRtrAdvInterval  = 198 * time.Second     // 0.33 * MaxRtrAdvInterval, per §6.2.1's default formula
	AdvDefaultLifetime = 3 * maxRtrAdvInterval // 1800s, §6.2.1's recommended default
)

// RFC 4861 §10 fixed constants governing initial-burst and solicited-reply
// timing.
const (
	maxInitialRtrAdvertisements = 3
	maxInitialRtrAdvertInterval = 16 * time.Second
	// MinDelayBetweenRAs is the floor between consecutive multicast RAs
	// (§6.2.4): an RA sooner than this after the last one is not sent.
	MinDelayBetweenRAs = 3 * time.Second
	maxRADelayTime     = 500 * time.Millisecond
)

// TentativeRetryInterval is how soon to retry a send that failed with
// EADDRNOTAVAIL: the kernel returns that when the interface has no usable
// source address, which right after an advertiser starts means the
// link-local is still tentative -- DAD runs for ~1s whenever the link
// (re)comes up, and both an XDP attach bouncing the link and the LAN address
// assignment happen immediately before advertising starts in this project's
// startup sequence. Transient by nature, so retry on roughly DAD's timescale
// rather than treating it as fatal.
const TentativeRetryInterval = 1 * time.Second

// Config carries the CPE-specific values that vary per LAN interface;
// everything else (timing, flags, hop limits) follows RFC 4861's
// recommended defaults.
type Config struct {
	// Prefix is advertised in a Prefix Information Option with the
	// Autonomous flag always set (RFC 4861 §4.6.2), so LAN clients SLAAC
	// an address out of it.
	Prefix netip.Prefix

	// OnLink sets the Prefix Information Option's L flag. True (the
	// DHCPv6-PD model's own distinct delegated /64: see
	// internal/lanprefix) tells LAN clients the whole prefix is directly
	// reachable, so they only route through this router for destinations
	// outside it. False (the NDProxy model's shared WAN /64: see
	// internal/wanextend) tells them the opposite -- route everything
	// through this router regardless of destination -- which is what
	// makes WAN-side NDProxy's answers the only way LAN-to-LAN and
	// LAN-to-WAN reachability happens, per RFC 4389 rather than requiring
	// LAN-side proxying too.
	OnLink bool

	ValidLifetime, PreferredLifetime time.Duration

	// RDNSSAddr, when valid, adds a Recursive DNS Server option (RFC 8106)
	// to every RA pointing LAN clients at it. It must be an address a DNS
	// proxy is *actually* listening on (RFC 7084 §L-11) -- so the caller
	// passes the concrete link-local address internal/dnsproxy bound, not a mere
	// "advertise RDNSS" flag: advertising a DNS server nothing answers on
	// would be worse than advertising none, and having Serve independently
	// re-resolve the address could diverge from what the proxy bound (e.g.
	// if the link-local was still tentative when the proxy started). The
	// zero netip.Addr means no RDNSS option. Its zone, if any, is local
	// metadata and never goes on the wire (see NewRDNSS).
	RDNSSAddr netip.Addr
}

// BuildRA assembles a Router Advertisement carrying cfg's prefix (as a
// Prefix Information Option, A flag always set and L set per cfg.OnLink),
// mac (as a Source Link-Layer Address option), and -- if cfg.RDNSSAddr is
// valid -- an RDNSS option pointing at it, with the given RouterLifetime:
// AdvDefaultLifetime while advertising, 0 on the way out (RFC 4861 §6.2.5),
// which withdraws the RDNSS server with it.
func BuildRA(cfg Config, lifetime time.Duration, mac net.HardwareAddr) *RouterAdvertisement {
	opts := Options{
		NewPrefixInformation(PrefixInformation{
			Prefix:            cfg.Prefix,
			OnLink:            cfg.OnLink,
			Autonomous:        true,
			ValidLifetime:     cfg.ValidLifetime,
			PreferredLifetime: cfg.PreferredLifetime,
		}),
		NewSourceLinkLayerAddress(mac),
	}
	if cfg.RDNSSAddr.IsValid() {
		opts = append(opts, NewRDNSS([]netip.Addr{cfg.RDNSSAddr}, lifetime))
	}
	return &RouterAdvertisement{
		RouterLifetime: lifetime,
		Options:        opts,
	}
}

// NextUnsolicitedInterval returns how long to wait before the next
// unsolicited RA, given sent RAs have already gone out: the first
// maxInitialRtrAdvertisements ramp in quickly (RFC 4861 §10, capped at
// maxInitialRtrAdvertInterval) so newly-attached hosts don't wait a full
// steady-state interval for their first RA, after which it settles into the
// jittered [minRtrAdvInterval, maxRtrAdvInterval] steady-state cadence of
// §6.2.4. It draws from r, so that an advertiser keeping its own generator
// stays deterministic.
func NextUnsolicitedInterval(sent int, r *rand.Rand) time.Duration {
	if sent < maxInitialRtrAdvertisements {
		return randInterval(0, maxInitialRtrAdvertInterval, r)
	}
	return randInterval(minRtrAdvInterval, maxRtrAdvInterval, r)
}

// ReplyDelay returns how long to delay an RA answering a Router
// Solicitation: up to maxRADelayTime, so routers on a link don't answer in
// sync (RFC 4861 §6.2.6, §10).
func ReplyDelay(r *rand.Rand) time.Duration {
	return randInterval(0, maxRADelayTime, r)
}

// randInterval returns a uniformly random duration in [min, max] (RFC 4861
// §6.2.4's randomization rule -- unlike RFC 3315 §14's jitter-around-a-base
// formula used elsewhere in this project, RFC 4861 picks uniformly across
// the whole configured range).
func randInterval(min, max time.Duration, r *rand.Rand) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(r.Float64()*float64(max-min))
}
