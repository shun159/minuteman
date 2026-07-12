package dhcpv4

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// lease records one client's currently-held (or offered) address and when
// it expires. An offered-but-not-yet-committed address is stored the same
// way, so a concurrent request from another client can't be handed the same
// address before the first client confirms it.
type lease struct {
	ip     netip.Addr
	expiry time.Time
}

// Pool is the address allocator for one LAN subnet: which addresses are
// free, which client holds which, and when leases expire. Like
// pkg/ndproxy's proxyState it's pure -- every method takes an explicit now
// instead of reading the clock, so it's unit-tested with no timers -- and,
// like the rest of minuteman's state, it's in-memory only (a CPE restart
// starts from an empty pool; clients recover by re-requesting, which
// Commit honours for any still-free in-subnet address). Not safe for
// concurrent use; server.go drives one Pool from a single per-interface
// goroutine.
type Pool struct {
	subnet    netip.Prefix
	serverIP  netip.Addr
	network   netip.Addr
	broadcast netip.Addr
	duration  time.Duration

	byClient map[string]lease
	byIP     map[netip.Addr]string
	declined map[netip.Addr]bool
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
		declined:  make(map[netip.Addr]bool),
	}, nil
}

// Offer picks an address for a DISCOVER from clientID and holds it (so a
// concurrent DISCOVER from another client won't be offered the same one),
// returning ok=false only if the pool is exhausted. It prefers, in order:
// the address clientID already holds (lease stability across restarts and
// retransmits), then a valid in-subnet requested address if free, then the
// lowest free address.
func (p *Pool) Offer(clientID string, requested netip.Addr, now time.Time) (netip.Addr, bool) {
	if l, ok := p.byClient[clientID]; ok && p.allocatable(l.ip) {
		return p.hold(clientID, l.ip, now), true
	}
	if p.allocatable(requested) && p.isFree(requested, clientID, now) {
		return p.hold(clientID, requested, now), true
	}
	if ip, ok := p.nextFree(clientID, now); ok {
		return p.hold(clientID, ip, now), true
	}
	return netip.Addr{}, false
}

// Commit binds requested to clientID for a REQUEST, returning ok=false when
// the server should answer with a NAK -- requested isn't a valid pool
// address, or it's held by a different client. requested is the address
// from the REQUEST (option 50 in SELECTING, or ciaddr in RENEWING/
// REBINDING). A request for a free in-subnet address the server never
// offered is still honoured, which is what lets a client recover its
// address after a CPE restart wiped the pool.
func (p *Pool) Commit(clientID string, requested netip.Addr, now time.Time) (netip.Addr, bool) {
	if !p.allocatable(requested) || !p.isFree(requested, clientID, now) {
		return netip.Addr{}, false
	}
	return p.hold(clientID, requested, now), true
}

// Release frees ip if it's currently leased to clientID (RFC 2131 §4.4.6's
// RELEASE). A mismatch is ignored -- a client can only release its own
// lease.
func (p *Pool) Release(clientID string, ip netip.Addr) {
	if owner, ok := p.byIP[ip]; ok && owner == clientID {
		p.clear(clientID)
	}
}

// Decline marks ip as unusable (a client found it already in use via ARP,
// RFC 2131 §4.4.5) so it's never offered again for this Pool's lifetime,
// and drops clientID's lease on it.
func (p *Pool) Decline(clientID string, ip netip.Addr) {
	if ip.Is4() {
		p.declined[ip] = true
	}
	if owner, ok := p.byIP[ip]; ok && owner == clientID {
		p.clear(clientID)
	}
}

// LeaseDuration is the pool's fixed lease length, exposed so the handler can
// emit matching lease-time options.
func (p *Pool) LeaseDuration() time.Duration { return p.duration }

// hold records (clientID -> ip) with a fresh expiry, clearing any previous
// lease for clientID and any previous owner of ip, and returns ip.
func (p *Pool) hold(clientID string, ip netip.Addr, now time.Time) netip.Addr {
	p.clear(clientID)
	if prev, ok := p.byIP[ip]; ok {
		delete(p.byClient, prev)
	}
	p.byClient[clientID] = lease{ip: ip, expiry: now.Add(p.duration)}
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

// allocatable reports whether ip is an address this pool may ever hand out:
// in-subnet, not the network/broadcast/server address, and not declined.
func (p *Pool) allocatable(ip netip.Addr) bool {
	return ip.Is4() && p.subnet.Contains(ip) &&
		ip != p.network && ip != p.broadcast && ip != p.serverIP &&
		!p.declined[ip]
}

// isFree reports whether ip can be given to forClient now: unowned, owned by
// forClient already, or owned by someone whose lease has expired.
func (p *Pool) isFree(ip netip.Addr, forClient string, now time.Time) bool {
	owner, ok := p.byIP[ip]
	if !ok || owner == forClient {
		return true
	}
	l := p.byClient[owner]
	return !now.Before(l.expiry)
}

// nextFree returns the lowest allocatable address free for forClient.
func (p *Pool) nextFree(forClient string, now time.Time) (netip.Addr, bool) {
	for ip := p.network.Next(); ip.IsValid() && p.subnet.Contains(ip); ip = ip.Next() {
		if p.allocatable(ip) && p.isFree(ip, forClient, now) {
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
