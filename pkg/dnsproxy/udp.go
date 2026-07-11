package dnsproxy

import (
	"net"
	"net/netip"
	"time"
)

// maxUDPMessageBytes is generous enough for any EDNS0 (RFC 6891) response a
// real-world resolver sends -- this package never parses a message, so
// there's no reason to size the buffer down to plain DNS's traditional
// 512-byte limit and risk silently truncating a larger one.
const maxUDPMessageBytes = 65535

// udpQueryTimeout bounds how long forwardUDPQuery waits for one upstream to
// answer before trying the next.
const udpQueryTimeout = 5 * time.Second

// serveUDP reads DNS queries from conn until it's closed (Serve's own
// shutdown path), forwarding each to upstreams and relaying the answer
// back to the querying client. Each query is handled in its own goroutine
// so one slow or unresponsive upstream exchange never blocks the next
// query arriving on the same listening socket.
func serveUDP(conn *net.UDPConn, upstreams []netip.Addr) {
	buf := make([]byte, maxUDPMessageBytes)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // conn closed
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go forwardUDPQuery(conn, from, query, upstreams)
	}
}

// forwardUDPQuery tries each of upstreams in order until one answers
// query, then relays that answer back to from via conn. If every upstream
// fails, the query is silently dropped -- the client's own resolver will
// retry per its usual timeout/retransmission behavior, the same as if this
// proxy weren't in the path at all.
func forwardUDPQuery(conn *net.UDPConn, from *net.UDPAddr, query []byte, upstreams []netip.Addr) {
	for _, upstream := range upstreams {
		answer, err := queryUpstreamUDP(upstream, query)
		if err != nil {
			continue
		}
		conn.WriteToUDP(answer, from)
		return
	}
}

// queryUpstreamUDP sends query to upstream over a fresh UDP socket (one per
// query, not pooled: DNS-over-UDP is a single datagram round trip, and a
// dedicated socket means the response can't be confused with any other
// concurrent query's) and returns its answer, bounded by udpQueryTimeout.
func queryUpstreamUDP(upstream netip.Addr, query []byte) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: upstream.AsSlice(), Port: dnsPort})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(udpQueryTimeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, maxUDPMessageBytes)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
