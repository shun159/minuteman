package dhcpv4

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNewRejectsInvalidPoolConfigBeforeOpeningSockets(t *testing.T) {
	// An IPv6 (non-IPv4) subnet must fail New synchronously -- NewPool
	// rejects it before any socket is opened, so this is testable without
	// privileges, and it proves a bad -dhcpv4 config surfaces as a startup
	// error rather than a background log line.
	cfgs := []InterfaceConfig{{
		Iface:     "doesnotmatter",
		ServerIP:  netip.MustParseAddr("2001:db8::1"),
		Subnet:    netip.MustParsePrefix("2001:db8::/64"),
		LeaseTime: time.Hour,
	}}
	if _, err := New(cfgs); err == nil {
		t.Fatal("New with a non-IPv4 subnet: want error, got nil")
	}
}

func TestNewRejectsEmptyConfig(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New with no interfaces: want error, got nil")
	}
}

// errConn is a fake conn whose recv fails immediately, standing in for a
// packet socket that hits a runtime read error.
type errConn struct{ err error }

func (c *errConn) recv() (*Message, error)                           { return nil, c.err }
func (c *errConn) send(*Message, netip.Addr, net.HardwareAddr) error { return nil }
func (c *errConn) Close() error                                      { return nil }

func TestServeOneReturnsRecvError(t *testing.T) {
	// serveOne must surface a runtime read error (Server.Serve then decides
	// whether it's a benign shutdown or a failure to report) rather than
	// exiting silently.
	cfg, pool := testConfig()
	want := errors.New("socket exploded")
	if got := serveOne(cfg, pool, &errConn{err: want}); !errors.Is(got, want) {
		t.Fatalf("serveOne returned %v, want %v", got, want)
	}
}
