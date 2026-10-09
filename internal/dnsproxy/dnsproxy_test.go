package dnsproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/proc"
)

var loopback = netip.MustParseAddr("127.0.0.1")

// udpUpstream answers each query with "answer:" and the query, or never
// if silent.
func udpUpstream(t *testing.T, silent bool) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback.AsSlice()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if !silent {
				conn.WriteToUDPAddrPort(append([]byte("answer:"), buf[:n]...), from)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// tcpUpstream answers each connection with what it read, upper-cased.
func tcpUpstream(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: loopback.AsSlice()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.AcceptTCP()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, _ := io.ReadAll(c)
				c.Write(bytes.ToUpper(b))
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

// freePort returns a loopback port free for TCP, likely for UDP too.
func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: loopback.AsSlice()})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// start starts the proxy on the loopback, returning the address it serves.
func start(t *testing.T, timeout time.Duration, upstreams ...netip.AddrPort) netip.AddrPort {
	t.Helper()
	port := freePort(t)
	spec, err := Spec(Config{ListenAddrs: []netip.Addr{loopback}, ListenPort: port, Upstreams: upstreams, queryTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	n := proc.NewNode("")
	sup, err := supervisor.Start(t.Context(), n, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { supervisor.Stop(context.Background(), n, sup) })
	return netip.AddrPortFrom(loopback, port)
}

func queryUDP(t *testing.T, proxy netip.AddrPort, q string) string {
	t.Helper()
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(proxy))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(q))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer to %q: %v", q, err)
	}
	return string(buf[:n])
}

func TestUDP(t *testing.T) {
	proxy := start(t, 0, udpUpstream(t, false))
	for _, q := range []string{"one", "two"} {
		if got := queryUDP(t, proxy, q); got != "answer:"+q {
			t.Errorf("answer %q", got)
		}
	}
}

// An upstream that doesn't answer is given up on for the next.
func TestUDPFallback(t *testing.T) {
	proxy := start(t, 100*time.Millisecond, udpUpstream(t, true), udpUpstream(t, false))
	if got := queryUDP(t, proxy, "q"); got != "answer:q" {
		t.Errorf("answer %q", got)
	}
}

// Queries are forwarded concurrently: one stuck on a silent upstream holds
// up no other.
func TestUDPConcurrent(t *testing.T) {
	slow := udpUpstream(t, true)
	fast := udpUpstream(t, false)
	proxy := start(t, 2*time.Second, slow, fast)
	begin := time.Now()
	done := make(chan string, 3)
	for _, q := range []string{"a", "b", "c"} {
		go func() { done <- queryUDP(t, proxy, q) }()
	}
	for range 3 {
		<-done
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Errorf("three queries took %v: forwarded one at a time", d)
	}
}

func TestTCP(t *testing.T) {
	proxy := start(t, 0, tcpUpstream(t))
	c, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(proxy))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("query over tcp"))
	c.CloseWrite()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "QUERY OVER TCP" {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestNoUpstreams(t *testing.T) {
	if _, err := Spec(Config{ListenAddrs: []netip.Addr{loopback}}); err == nil {
		t.Error("Spec without upstreams succeeded")
	}
}

// A port already taken fails the start, rather than surfacing later.
func TestBindFailure(t *testing.T) {
	taken, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback.AsSlice()})
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	spec, _ := Spec(Config{
		ListenAddrs: []netip.Addr{loopback},
		ListenPort:  uint16(taken.LocalAddr().(*net.UDPAddr).Port),
		Upstreams:   []netip.AddrPort{netip.AddrPortFrom(loopback, 53)},
	})
	if _, err := supervisor.Start(t.Context(), proc.NewNode(""), spec); err == nil {
		t.Error("start on a taken port succeeded")
	}
}
