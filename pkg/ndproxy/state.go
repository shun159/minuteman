package ndproxy

import (
	"net/netip"
	"time"
)

// RFC 4861 §10: retransmission timing for the proxy's own LAN-side probes.
const (
	maxMulticastSolicit = 3               // MAX_MULTICAST_SOLICIT
	probeRetransTimer   = 1 * time.Second // RetransTimer default
)

// activeTTL bounds how long a confirmed-active target is trusted before
// the next WAN Neighbor Solicitation for it triggers a fresh LAN probe
// instead of an immediate reply -- long enough that normal traffic
// doesn't cause constant re-probing (an upstream neighbor cache entry is
// typically reused for tens of seconds to minutes before it's
// re-solicited), short enough that a LAN host going away is eventually
// noticed rather than proxied forever. Not RFC-mandated; a CPE-local
// policy choice.
const activeTTL = 5 * time.Minute

// pendingProbe tracks one target currently being verified on the LAN
// side: how many Neighbor Solicitation probes have been sent so far, when
// the next one is due, and who on the WAN side is waiting for the answer.
type pendingProbe struct {
	attempts  int
	nextProbe time.Time
	solicitor netip.Addr
}

// activeEntry tracks one target confirmed alive behind a specific LAN
// interface.
type activeEntry struct {
	iface       string
	confirmedAt time.Time
}

// pendingReply is a Neighbor Advertisement the caller should send on the
// WAN side, addressed per RFC 4861 §7.2.4 (solicited: unicast back to
// Solicitor; unsolicited/DAD-style: multicast -- see conn.sendAdvertisement,
// which already implements that rule from Solicitor's validity).
type pendingReply struct {
	Target    netip.Addr
	Solicitor netip.Addr
	Iface     string
}

// expiredActive is one active entry sweep dropped for staleness -- the
// counterpart to onLANAdvert's activation, so a caller that installed a
// host route in response to activation (Serve's OnActive) knows which
// target/interface pair to remove it for.
type expiredActive struct {
	Target netip.Addr
	Iface  string
}

// proxyState is the pure decision logic behind Serve: which targets are
// being actively probed on the LAN side, which are confirmed active, and
// what to do next given a WAN solicitation, a LAN advertisement, or a
// periodic timer tick. It has no I/O of its own -- every method takes an
// explicit now instead of reading the clock, so tests drive it with fake
// timestamps and never need a real timer or socket.
type proxyState struct {
	pending map[netip.Addr]*pendingProbe
	active  map[netip.Addr]activeEntry
}

func newProxyState() *proxyState {
	return &proxyState{
		pending: make(map[netip.Addr]*pendingProbe),
		active:  make(map[netip.Addr]activeEntry),
	}
}

// onWANSolicit records that solicitor asked about target on the WAN side
// and reports what the caller should do:
//   - reply non-nil: target is already confirmed active and fresh (within
//     activeTTL) -- the caller should send this Neighbor Advertisement
//     immediately, no LAN probing needed.
//   - probe true: target is unknown, or its active entry has expired --
//     the caller should send a Neighbor Solicitation probe out every LAN
//     interface.
//
// If a probe for target is already in flight, both returns are
// nil/false: sending a second, duplicate probe would be wasteful, and the
// already-pending probe's eventual match (or give-up) covers this
// solicitor too -- only the most recent solicitor is kept, since RFC 4861
// doesn't require answering every asker individually, just resolving the
// target once.
func (s *proxyState) onWANSolicit(now time.Time, target, solicitor netip.Addr) (reply *pendingReply, probe bool) {
	if a, ok := s.active[target]; ok && now.Sub(a.confirmedAt) < activeTTL {
		return &pendingReply{Target: target, Solicitor: solicitor, Iface: a.iface}, false
	}
	if p, already := s.pending[target]; already {
		p.solicitor = solicitor
		return nil, false
	}
	s.pending[target] = &pendingProbe{attempts: 1, nextProbe: now.Add(probeRetransTimer), solicitor: solicitor}
	return nil, true
}

// onLANAdvert matches a Neighbor Advertisement for target arriving on
// iface against a pending probe. ok is false if there's no matching
// pending probe (an unsolicited/stray NA, or one for a target that
// already gave up) -- the caller should ignore it. Otherwise target moves
// from pending to active (behind iface) and reply is the Neighbor
// Advertisement to send on the WAN side.
func (s *proxyState) onLANAdvert(now time.Time, iface string, target netip.Addr) (reply *pendingReply, ok bool) {
	p, ok := s.pending[target]
	if !ok {
		return nil, false
	}
	delete(s.pending, target)
	s.active[target] = activeEntry{iface: iface, confirmedAt: now}
	return &pendingReply{Target: target, Solicitor: p.solicitor, Iface: iface}, true
}

// sweep runs on every periodic tick. retransmit lists targets whose next
// probe is due (RFC 4861 §10's RetransTimer cadence) -- the caller should
// resend a Neighbor Solicitation probe for each, out every LAN interface.
// gaveUp lists targets that exhausted maxMulticastSolicit attempts without
// a reply and have been dropped from pending -- no WAN reply was ever
// sent for them, correctly not claiming a target that doesn't exist.
// expired lists active entries older than activeTTL, now dropped -- the
// next WAN solicitation for one of them starts a fresh probe, but the
// caller is told now (rather than left to notice on next solicit) so it
// can undo whatever onLANAdvert's activation told it to do (Serve's
// OnActive/OnInactive).
func (s *proxyState) sweep(now time.Time) (retransmit, gaveUp []netip.Addr, expired []expiredActive) {
	for target, p := range s.pending {
		if now.Before(p.nextProbe) {
			continue
		}
		if p.attempts >= maxMulticastSolicit {
			delete(s.pending, target)
			gaveUp = append(gaveUp, target)
			continue
		}
		p.attempts++
		p.nextProbe = now.Add(probeRetransTimer)
		retransmit = append(retransmit, target)
	}
	for target, a := range s.active {
		if now.Sub(a.confirmedAt) >= activeTTL {
			delete(s.active, target)
			expired = append(expired, expiredActive{Target: target, Iface: a.iface})
		}
	}
	return retransmit, gaveUp, expired
}
