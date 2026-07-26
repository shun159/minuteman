package routeradvert

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// RFC 4861 §6.2.1 default Router Configuration Variables.
const (
	maxRtrAdvInterval  = 600 * time.Second
	minRtrAdvInterval  = 198 * time.Second     // 0.33 * MaxRtrAdvInterval, per §6.2.1's default formula
	advDefaultLifetime = 3 * maxRtrAdvInterval // 1800s, §6.2.1's recommended default
)

// RFC 4861 §10 fixed constants governing initial-burst and solicited-reply
// timing.
const (
	maxInitialRtrAdvertisements = 3
	maxInitialRtrAdvertInterval = 16 * time.Second
	minDelayBetweenRAs          = 3 * time.Second
	maxRADelayTime              = 500 * time.Millisecond
)

// tentativeRetryInterval is how soon to retry a send that failed with
// EADDRNOTAVAIL: the kernel returns that when the interface has no usable
// source address, which right after Serve starts means the link-local is
// still tentative -- DAD runs for ~1s whenever the link (re)comes up, and
// both an XDP attach bouncing the link and the LAN address assignment
// happen immediately before Serve in this project's startup sequence.
// Transient by nature, so retry on roughly DAD's timescale rather than
// treating it as fatal.
const tentativeRetryInterval = 1 * time.Second

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
	// passes the concrete link-local address pkg/dnsproxy bound, not a mere
	// "advertise RDNSS" flag: advertising a DNS server nothing answers on
	// would be worse than advertising none, and having Serve independently
	// re-resolve the address could diverge from what the proxy bound (e.g.
	// if the link-local was still tentative when the proxy started). The
	// zero netip.Addr means no RDNSS option. Its zone, if any, is local
	// metadata and never goes on the wire (see NewRDNSS).
	RDNSSAddr netip.Addr
}

// Updater carries Config changes into a running Serve, so a caller whose
// advertised prefix or lifetimes changed can refresh them without
// cancelling and restarting the goroutine.
//
// Restarting would be equivalent but for one thing: cancellation is Serve's
// *shutdown* path, so it emits RFC 4861 §6.2.5's RouterLifetime=0
// advertisement -- and, since the RDNSS option's lifetime tracks the router
// lifetime (see buildRA), an RDNSS Lifetime=0 with it. Every LAN client is
// told this router is going away and its DNS server is unusable, moments
// before the replacement worker announces both again. Updating in place
// keeps that shutdown signal for actual shutdowns; see
// internal/lanprefix.RAManager, which reaches here on every DHCPv6-PD Renew.
//
// The zero Updater is unusable; call NewUpdater.
type Updater struct {
	ch chan Config
}

// NewUpdater returns an Updater ready to be passed to Serve.
func NewUpdater() *Updater {
	return &Updater{ch: make(chan Config, 1)}
}

// Set makes cfg the Config Serve advertises from its next send onwards.
//
// It never blocks: the channel is size-1 latest-wins, so an update Serve
// hasn't picked up yet is replaced rather than queued -- only the newest
// Config is meaningful, the same coalescing cmd/minuteman's WAN-change
// signal does. Set is for a single producer goroutine (minuteman's RA
// managers each drive their workers from one), and is safe alongside the
// Serve consuming the channel.
func (u *Updater) Set(cfg Config) {
	select {
	case <-u.ch: // drop an update Serve hasn't consumed: cfg supersedes it
	default:
	}
	select {
	case u.ch <- cfg:
	default:
		// Unreachable with a single producer -- the drain above emptied
		// the one slot and only this goroutine fills it. Non-blocking
		// anyway, so misuse can never deadlock a caller here.
	}
}

// Serve sends RFC 4861 Router Advertisements on ifaceName: periodically
// (unsolicited, ramping from a fast initial burst per §10's
// MAX_INITIAL_RTR_ADVERTISEMENTS/MAX_INITIAL_RTR_ADVERT_INTERVAL to the
// jittered [MinRtrAdvInterval, MaxRtrAdvInterval] steady-state cadence of
// §6.2.4) and in response to inbound Router Solicitations (rate-limited to
// once per minDelayBetweenRAs, delayed by up to maxRADelayTime to avoid
// synchronized replies, per §10).
//
// updates, when non-nil, replaces cfg while Serve runs (see Updater); a new
// Config that differs from the current one is advertised promptly rather
// than at the next scheduled RA, still respecting §6.2.4's
// MIN_DELAY_BETWEEN_RAS floor between consecutive multicast RAs. A nil
// Updater means cfg is fixed for this Serve's lifetime.
//
// Blocks until ctx is cancelled, at which point it sends one final RA with
// RouterLifetime=0 (RFC 4861 §6.2.5, best-effort -- tells already-configured
// hosts to stop treating this router as a default) before returning nil. A
// non-nil error means opening the socket or a send failed outright; ctx
// cancellation itself always yields a nil return.
func Serve(ctx context.Context, ifaceName string, cfg Config, updates *Updater) error {
	conn, err := Listen(ifaceName)
	if err != nil {
		return err
	}
	defer conn.Close()

	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("routeradvert: looking up interface %s: %w", ifaceName, err)
	}
	mac := ifi.HardwareAddr

	solicitations := conn.Solicitations()

	// A nil channel blocks forever in the select below, which is exactly
	// what a caller passing no Updater wants.
	var updateCh <-chan Config
	if updates != nil {
		updateCh = updates.ch
	}

	next := time.Now() // send the first RA immediately
	sent := 0
	var lastSent time.Time

	for {
		wait := max(0, time.Until(next))
		timer := time.NewTimer(wait)

		select {
		case <-ctx.Done():
			timer.Stop()
			_ = conn.SendAdvertisement(buildRA(cfg, 0, mac)) // best-effort
			return nil

		case <-timer.C:
			if err := conn.SendAdvertisement(buildRA(cfg, advDefaultLifetime, mac)); err != nil {
				if errors.Is(err, unix.EADDRNOTAVAIL) {
					next = time.Now().Add(tentativeRetryInterval) // see tentativeRetryInterval
					continue
				}
				return fmt.Errorf("routeradvert: sending unsolicited RA on %s: %w", ifaceName, err)
			}
			lastSent = time.Now()
			sent++
			next = lastSent.Add(nextUnsolicitedInterval(sent))

		case newCfg := <-updateCh:
			timer.Stop()
			if newCfg == cfg {
				continue // nothing LAN clients would see differently
			}
			cfg = newCfg
			// Announce the change instead of sitting on it for up to
			// MaxRtrAdvInterval, but never breach §6.2.4's floor on
			// consecutive multicast RAs.
			next = time.Now()
			if earliest := lastSent.Add(minDelayBetweenRAs); earliest.After(next) {
				next = earliest
			}

		case _, ok := <-solicitations:
			timer.Stop()
			if !ok {
				return fmt.Errorf("routeradvert: socket on %s closed unexpectedly", ifaceName)
			}
			if time.Since(lastSent) < minDelayBetweenRAs {
				continue // a recent RA already answers this solicitation
			}
			time.Sleep(randInterval(0, maxRADelayTime)) // §10: avoid synchronized replies
			if err := conn.SendAdvertisement(buildRA(cfg, advDefaultLifetime, mac)); err != nil {
				if errors.Is(err, unix.EADDRNOTAVAIL) {
					continue // still tentative; the pending unsolicited RA will cover this host
				}
				return fmt.Errorf("routeradvert: sending solicited RA on %s: %w", ifaceName, err)
			}
			lastSent = time.Now()
		}
	}
}

// buildRA assembles a Router Advertisement carrying cfg's prefix (as a
// Prefix Information Option, A flag always set and L set per cfg.OnLink),
// mac (as a Source Link-Layer Address option), and -- if cfg.RDNSSAddr is
// valid -- an RDNSS option pointing at it, with the given RouterLifetime.
func buildRA(cfg Config, lifetime time.Duration, mac net.HardwareAddr) *RouterAdvertisement {
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

// nextUnsolicitedInterval returns how long to wait before the next
// unsolicited RA, given sent RAs have already gone out on this Conn: the
// first maxInitialRtrAdvertisements ramp in quickly (RFC 4861 §10, capped at
// maxInitialRtrAdvertInterval) so newly-attached hosts don't wait a full
// steady-state interval for their first RA, after which it settles into the
// jittered [minRtrAdvInterval, maxRtrAdvInterval] steady-state cadence of
// §6.2.4.
func nextUnsolicitedInterval(sent int) time.Duration {
	if sent < maxInitialRtrAdvertisements {
		return randInterval(0, maxInitialRtrAdvertInterval)
	}
	return randInterval(minRtrAdvInterval, maxRtrAdvInterval)
}

// randInterval returns a uniformly random duration in [min, max] (RFC 4861
// §6.2.4's randomization rule -- unlike RFC 3315 §14's jitter-around-a-base
// formula used elsewhere in this project, RFC 4861 picks uniformly across
// the whole configured range).
func randInterval(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(rand.Float64()*float64(max-min))
}
