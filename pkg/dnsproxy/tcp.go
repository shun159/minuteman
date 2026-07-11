package dnsproxy

import (
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// tcpDialTimeout bounds how long relayTCP waits to connect to one upstream
// before trying the next.
const tcpDialTimeout = 5 * time.Second

// serveTCP accepts DNS-over-TCP connections on ln until it's closed
// (Serve's own shutdown path), relaying each accepted connection to the
// first reachable upstream.
func serveTCP(ln *net.TCPListener, upstreams []netip.Addr) {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			return // ln closed
		}
		go relayTCP(conn, upstreams)
	}
}

// relayTCP proxies client's bytes to and from the first of upstreams that
// accepts a connection, verbatim in both directions -- a full byte-level
// relay rather than parsing individual length-prefixed DNS messages
// (RFC 7766 §6.2.1 allows pipelining multiple queries on one connection,
// which a byte-level relay handles for free without this package ever
// needing to frame messages itself). Returns once both directions have
// finished copying (i.e. one side closed).
func relayTCP(client *net.TCPConn, upstreams []netip.Addr) {
	defer client.Close()

	var upstream net.Conn
	for _, addr := range upstreams {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr.String(), strconv.Itoa(dnsPort)), tcpDialTimeout)
		if err == nil {
			upstream = conn
			break
		}
	}
	if upstream == nil {
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, client)
		if u, ok := upstream.(*net.TCPConn); ok {
			u.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upstream)
		client.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
}
