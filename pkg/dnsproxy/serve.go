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
// the RFC's own framing. That also means it has no wire format of its own
// to unit test; pkg/ndproxy and pkg/routeradvert's raw-socket I/O are the
// same way, and this package's own correctness is instead exercised by
// test/netns's rig end-to-end.
package dnsproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// dnsPort is the standard DNS port (RFC 1035 §4.2), used on both the
// LAN-facing listen side and the upstream side.
const dnsPort = 53

// Config is Serve's configuration.
type Config struct {
	// ListenAddrs are the LAN-facing addresses to listen on, port 53 over
	// both UDP and TCP -- typically each -lan interface's gateway IP, so
	// LAN clients pointed at their default gateway for DNS reach this
	// proxy without any extra configuration of their own.
	ListenAddrs []netip.Addr

	// Upstreams are the DNS server(s) to forward to, port 53. Tried in
	// order (UDP: per query; TCP: per accepted connection) until one
	// answers. Should be addresses reachable directly over the WAN's own
	// IPv6 connectivity (e.g. DHCPv6 OPTION_DNS_SERVERS) -- an address
	// only reachable through the DS-Lite softwire itself would defeat
	// this package's whole purpose, and in a typical DS-Lite deployment
	// (IPv6-only WAN) simply isn't reachable at all from the CPE's own
	// non-tunneled IPv4 routing table.
	Upstreams []netip.Addr
}

// Serve listens on every cfg.ListenAddrs address (UDP and TCP, port 53)
// and forwards queries to cfg.Upstreams until ctx is cancelled, at which
// point every socket is closed and Serve returns nil. A non-nil return
// means either cfg had no Upstreams configured, or opening a listening
// socket failed outright.
func Serve(ctx context.Context, cfg Config) error {
	if len(cfg.Upstreams) == 0 {
		return fmt.Errorf("dnsproxy: no upstream DNS servers configured")
	}

	var udpConns []*net.UDPConn
	var tcpListeners []*net.TCPListener
	closeAll := func() {
		for _, c := range udpConns {
			c.Close()
		}
		for _, l := range tcpListeners {
			l.Close()
		}
	}

	for _, addr := range cfg.ListenAddrs {
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: addr.AsSlice(), Port: dnsPort})
		if err != nil {
			closeAll()
			return fmt.Errorf("dnsproxy: listening on %s:%d/udp: %w", addr, dnsPort, err)
		}
		udpConns = append(udpConns, udpConn)

		tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: addr.AsSlice(), Port: dnsPort})
		if err != nil {
			closeAll()
			return fmt.Errorf("dnsproxy: listening on %s:%d/tcp: %w", addr, dnsPort, err)
		}
		tcpListeners = append(tcpListeners, tcpListener)
	}

	var wg sync.WaitGroup
	for _, c := range udpConns {
		wg.Add(1)
		go func(c *net.UDPConn) {
			defer wg.Done()
			serveUDP(c, cfg.Upstreams)
		}(c)
	}
	for _, l := range tcpListeners {
		wg.Add(1)
		go func(l *net.TCPListener) {
			defer wg.Done()
			serveTCP(l, cfg.Upstreams)
		}(l)
	}

	<-ctx.Done()
	closeAll() // unblocks every serveUDP/serveTCP loop, see their own doc comments
	wg.Wait()
	return nil
}
