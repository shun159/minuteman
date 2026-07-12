package dhcpv4

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// offerHoldTime is how long an offered-but-not-yet-committed address is
// reserved for the client it was offered to. RFC 2131 lets a server reserve
// an offered address but expects it back in the pool quickly if no
// DHCPREQUEST follows (a client that selected a different server, or went
// away, or a stray/spoofed DISCOVER). Short enough that those can't tie up
// the pool for a whole lease, long enough for a normal client's REQUEST
// (sent within a second or two of the OFFER) to arrive.
const offerHoldTime = 60 * time.Second

// declineQuarantine is how long an address a client DHCPDECLINEd (found in
// use via ARP, RFC 2131 §4.4.5) is withheld before it's offered again.
// Bounded, not permanent, so a transient conflict — or a client declining
// addresses maliciously — can't remove an address from the pool for the
// process's whole lifetime.
const declineQuarantine = time.Hour

// bindingState distinguishes an address merely offered (DHCPOFFER sent, no
// DHCPREQUEST yet) from one committed to a client (DHCPACK sent). They differ
// only in how long they're held (offerHoldTime vs. the full lease) and in
// whether Offer may downgrade them, but a bound client's DISCOVER must not
// silently shorten its lease.
type bindingState uint8

const (
	bindingOffered bindingState = iota
	bindingCommitted
)

type lease struct {
	ip     netip.Addr
	expiry time.Time
	state  bindingState
}

// Pool is the address allocator for one LAN subnet: which addresses are
// free, which client holds which (offered or committed), when those expire,
// and which are quarantined by a DHCPDECLINE. Like pkg/ndproxy's proxyState
// it's pure — every method takes an explicit now instead of reading the
// clock, so it's unit-tested with no timers — and, like the rest of
// minuteman's state, it's in-memory only. Not safe for concurrent use;
// server.go drives one Pool from a single per-interface goroutine.
type Pool struct {
	subnet    netip.Prefix
	serverIP  netip.Addr
	network   netip.Addr
	broadcast netip.Addr
	duration  time.Duration

	byClient map[string]lease
	byIP     map[netip.Addr]string
	declined map[netip.Addr]time.Time // address -> quarantine-until
}

// NewPool builds a Pool serving subnet, excluding the network, broadcast,
// and serverIP addresses from allocation. subnet must be IPv4 with a prefix
// length leaving room for at least one host address.
func NewPool(subnet netip.Prefix, serverIP netip.Addr, duration time.Duration) (*Pool, error) {
	subnet = subnet.Masked()
	if !subnet.Addr().Is4() {
		return nil, fmt.Errorf("dhcpv4: pool subnet %s must be IPv4", subnet)
	}
	if subnet.Bits() < 1 || subnet.Bits() > 30 {
		return nil, fmt.Errorf("dhcpv4: pool subnet %s has no usable host range", subnet)
	}
	if !serverIP.Is4() || !subnet.Contains(serverIP) {
		return nil, fmt.Errorf("dhcpv4: server IP %s is not within pool subnet %s", serverIP, subnet)
	}
	return &Pool{
		subnet:    subnet,
		serverIP:  serverIP,
		network:   subnet.Addr(),
		broadcast: lastAddr(subnet),
		duration:  duration,
		byClient:  make(map[string]lease),
		byIP:      make(map[netip.Addr]string),
		declined:  make(map[netip.Addr]time.Time),
	}, nil
}

// Offer reserves an address for a DISCOVER from clientID and returns it,
// with ok=false only when the pool is exhausted. It prefers, in order: the
// address clientID already holds (lease stability across retransmits — and,
// after a CPE restart, the address a returning client re-DISCOVERs for is
// re-allocated freshly here since the pool started empty), then a valid
// in-subnet requested address if free, then the lowest free address. The
// reservation is held only for offerHoldTime; a client that never REQUESTs
// loses it back to the pool quickly rather than for the full lease.
func (p *Pool) Offer(clientID string, requested netip.Addr, now time.Time) (netip.Addr, bool) {
	if l, ok := p.byClient[clientID]; ok && !p.expired(l, now) && p.allocatable(l.ip, now) {
		return p.hold(clientID, l.ip, now, l.state), true // keep committed state if already bound
	}
	if p.allocatable(requested, now) && p.isFree(requested, clientID, now) {
		return p.hold(clientID, requested, now, bindingOffered), true
	}
	if ip, ok := p.nextFree(clientID, now); ok {
		return p.hold(clientID, ip, now, bindingOffered), true
	}
	return netip.Addr{}, false
}

// Binding returns the address clientID currently holds (offered or
// committed) if the lease hasn't expired. The handler uses it to decide
// whether a REQUEST is for an address this server actually gave the client
// (rather than committing any free address, which RFC 2131 §4.3.2 forbids
// for a client the server has no record of).
func (p *Pool) Binding(clientID string, now time.Time) (netip.Addr, bool) {
	l, ok := p.byClient[clientID]
	if !ok || p.expired(l, now) {
		return netip.Addr{}, false
	}
	return l.ip, true
}

// Commit binds ip to clientID for the full lease duration (a DHCPACK). The
// caller is responsible for having established, via Binding, that ip is the
// address this server offered or already leased to clientID.
func (p *Pool) Commit(clientID string, ip netip.Addr, now time.Time) {
	p.hold(clientID, ip, now, bindingCommitted)
}

// CancelOffer drops clientID's reservation if it's only an offer (not a
// committed lease) — used when a REQUEST reveals the client selected a
// different DHCP server, so its offered address returns to the pool at once
// instead of waiting out offerHoldTime.
func (p *Pool) CancelOffer(clientID string) {
	if l, ok := p.byClient[clientID]; ok && l.state == bindingOffered {
		p.clear(clientID)
	}
}

// Release frees ip if it's currently held by clientID (RFC 2131 §4.4.6's
// RELEASE). A mismatch is ignored — a client can only release its own lease.
func (p *Pool) Release(clientID string, ip netip.Addr) {
	if owner, ok := p.byIP[ip]; ok && owner == clientID {
		p.clear(clientID)
	}
}

// Decline quarantines ip (RFC 2131 §4.4.5's DHCPDECLINE: the client found it
// already in use) and drops clientID's lease on it — but only if ip is
// actually held by clientID, so a client can't quarantine arbitrary pool
// addresses it was never given. The quarantine is time-bounded
// (declineQuarantine), not permanent.
func (p *Pool) Decline(clientID string, ip netip.Addr, now time.Time) {
	if owner, ok := p.byIP[ip]; !ok || owner != clientID {
		return
	}
	p.declined[ip] = now.Add(declineQuarantine)
	p.clear(clientID)
}

// LeaseDuration is the pool's fixed lease length, exposed so the handler can
// emit matching lease-time options.
func (p *Pool) LeaseDuration() time.Duration { return p.duration }

// hold records (clientID -> ip) with the expiry appropriate to state,
// clearing any previous lease for clientID and any previous owner of ip.
func (p *Pool) hold(clientID string, ip netip.Addr, now time.Time, state bindingState) netip.Addr {
	p.clear(clientID)
	if prev, ok := p.byIP[ip]; ok {
		delete(p.byClient, prev)
	}
	dur := offerHoldTime
	if state == bindingCommitted {
		dur = p.duration
	}
	p.byClient[clientID] = lease{ip: ip, expiry: now.Add(dur), state: state}
	p.byIP[ip] = clientID
	return ip
}

// clear removes clientID's lease and its reverse index, if any.
func (p *Pool) clear(clientID string) {
	if l, ok := p.byClient[clientID]; ok {
		delete(p.byIP, l.ip)
		delete(p.byClient, clientID)
	}
}

func (p *Pool) expired(l lease, now time.Time) bool { return !now.Before(l.expiry) }

// allocatable reports whether ip is an address this pool may hand out:
// in-subnet, not the network/broadcast/server address, and not currently
// quarantined by a DHCPDECLINE (an elapsed quarantine is cleared here).
func (p *Pool) allocatable(ip netip.Addr, now time.Time) bool {
	if until, ok := p.declined[ip]; ok {
		if now.Before(until) {
			return false
		}
		delete(p.declined, ip) // quarantine elapsed; address is eligible again
	}
	return ip.Is4() && p.subnet.Contains(ip) &&
		ip != p.network && ip != p.broadcast && ip != p.serverIP
}

// isFree reports whether ip can be given to forClient now: unowned, owned by
// forClient already, or owned by someone whose lease has expired.
func (p *Pool) isFree(ip netip.Addr, forClient string, now time.Time) bool {
	owner, ok := p.byIP[ip]
	if !ok || owner == forClient {
		return true
	}
	return p.expired(p.byClient[owner], now)
}

// nextFree returns the lowest allocatable address free for forClient.
func (p *Pool) nextFree(forClient string, now time.Time) (netip.Addr, bool) {
	for ip := p.network.Next(); ip.IsValid() && p.subnet.Contains(ip); ip = ip.Next() {
		if p.allocatable(ip, now) && p.isFree(ip, forClient, now) {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// lastAddr returns the last address in prefix (its broadcast address for
// IPv4): the network address with every host bit set.
func lastAddr(prefix netip.Prefix) netip.Addr {
	a := prefix.Addr().As4()
	hostBits := 32 - prefix.Bits()
	v := binary.BigEndian.Uint32(a[:]) | uint32((uint64(1)<<hostBits)-1)
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return netip.AddrFrom4(out)
}
