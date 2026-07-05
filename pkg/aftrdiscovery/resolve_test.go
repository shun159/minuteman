package aftrdiscovery

import (
	"net/netip"
	"testing"
)

func TestParseDNSServers(t *testing.T) {
	a := netip.MustParseAddr("fd00:1::1")
	b := netip.MustParseAddr("fd00:1::2")
	data := append(append([]byte{}, a.AsSlice()...), b.AsSlice()...)

	got, err := parseDNSServers(data)
	if err != nil {
		t.Fatalf("parseDNSServers: %v", err)
	}
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("parseDNSServers() = %v, want [%v %v]", got, a, b)
	}
}

func TestParseDNSServersBadLength(t *testing.T) {
	if _, err := parseDNSServers(make([]byte, 17)); err == nil {
		t.Fatal("expected error for a non-multiple-of-16 length, got nil")
	}
}
