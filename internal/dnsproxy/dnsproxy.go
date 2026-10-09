// Package dnsproxy implements the DNS proxy RFC 6333 recommends a DS-Lite
// B4 element run (the B4 SHOULD act as a DNS proxy for its LAN clients): it
// listens on the LAN side and forwards each query verbatim to upstream DNS
// server(s) reachable natively over IPv6 (typically the WAN's own DHCPv6
// OPTION_DNS_SERVERS -- see pkg/aftrdiscovery.Result.DNSServers), so a LAN
// client's DNS lookups never need to round-trip through the DS-Lite
// IPv4-in-IPv6 softwire and the AFTR's NAT44 the way an ordinary IPv4 DNS
// query to those same servers otherwise would (xdp_dslite_encap has no way
// to distinguish a DNS packet from any other IPv4 traffic, so without this
// package every LAN DNS query would take the full softwire round trip).
//
// This package is opaque to DNS itself: it relays whatever bytes it
// receives and whatever bytes come back, with no message parsing, caching,
// or rewriting of any kind -- a forwarding proxy, not a resolver, matching
// the RFC's own framing.
//
// It is a molecule supervision tree, one UDP listener and one TCP listener
// per listen address; see Spec.
package dnsproxy

import (
	"cmp"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/net/gentcpacceptor"
)

// Port is the standard DNS port (RFC 1035 §4.2).
const Port = 53

// Config is the proxy's configuration.
type Config struct {
	// ListenAddrs are the LAN-facing addresses to listen on, over both UDP
	// and TCP -- typically each -lan interface's gateway IP, so LAN clients
	// pointed at their default gateway for DNS reach this proxy without any
	// extra configuration of their own. A link-local address carries its
	// zone: fe80::/10 isn't unique without it, so the kernel needs it to
	// pick the right interface to bind on.
	ListenAddrs []netip.Addr
	// ListenPort is the port to listen on; Port if zero.
	ListenPort uint16

	// Upstreams are the DNS server(s) to forward to. Tried in order (UDP:
	// per query; TCP: per accepted connection) until one answers. Should be
	// addresses reachable directly over the WAN's own IPv6 connectivity
	// (e.g. DHCPv6 OPTION_DNS_SERVERS) -- an address only reachable through
	// the DS-Lite softwire itself would defeat this package's whole
	// purpose, and in a typical DS-Lite deployment (IPv6-only WAN) simply
	// isn't reachable at all from the CPE's own non-tunneled IPv4 routing
	// table.
	Upstreams []netip.AddrPort

	// queryTimeout is udpQueryTimeout if zero; tests shorten it.
	queryTimeout time.Duration
}

// Spec is the supervision tree of the proxy:
//
//	dnsproxy (one_for_one)
//	├── udp <addr>   the UDP listener, an Async per query in flight
//	├── tcp <addr>   a gentcpacceptor listener relaying each connection
//	└── ...          the same for each listen address
//
// Each listener is started -- its socket bound -- before the tree's start
// returns, so a caller that advertises these addresses to LAN clients (RFC
// 8106 RDNSS) does so only once something is really listening on them. The
// UDP listener of an address starts first, and waits out a link-local
// address still DAD-tentative (see bindRetries), so that its TCP listener
// then binds at once.
func Spec(cfg Config) (supervisor.Spec, error) {
	if len(cfg.Upstreams) == 0 {
		return supervisor.Spec{}, errors.New("dnsproxy: no upstream DNS servers configured")
	}
	port := cfg.ListenPort
	if port == 0 {
		port = Port
	}
	var children []supervisor.ChildSpec
	for _, addr := range cfg.ListenAddrs {
		ap := netip.AddrPortFrom(addr, port)
		u := udpListener{addr: ap, upstreams: cfg.Upstreams, timeout: cmp.Or(cfg.queryTimeout, udpQueryTimeout)}
		children = append(children, supervisor.ChildSpec{
			ID:    "udp " + ap.String(),
			Start: supervisor.StartFunc(u.start),
		})
		tcp := gentcpacceptor.NewRawListener(gentcpacceptor.Spec{
			Addr: net.JoinHostPort(addr.String(), strconv.Itoa(int(port))),
		}, relay(cfg.Upstreams))
		children = append(children, tcp.ChildSpec("tcp "+ap.String()))
	}
	return supervisor.Spec{
		Name:     molecule.Local("dnsproxy"),
		Strategy: supervisor.OneForOne,
		Children: children,
	}, nil
}

// Upstreams returns addrs on the DNS port.
func Upstreams(addrs []netip.Addr) []netip.AddrPort {
	ups := make([]netip.AddrPort, len(addrs))
	for i, a := range addrs {
		ups[i] = netip.AddrPortFrom(a, Port)
	}
	return ups
}
