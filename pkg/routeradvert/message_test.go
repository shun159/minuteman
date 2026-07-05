package routeradvert

import (
	"bytes"
	"testing"
	"time"
)

func TestRouterAdvertisementMarshalNoOptions(t *testing.T) {
	ra := RouterAdvertisement{
		CurHopLimit:    64,
		RouterLifetime: 1800 * time.Second,
	}
	got := ra.Marshal()
	want := []byte{
		134, 0, 0x00, 0x00, // Type, Code, Checksum (kernel-computed, left zero)
		64,         // Cur Hop Limit
		0x00,       // M/O flags + Reserved
		0x07, 0x08, // Router Lifetime = 1800
		0x00, 0x00, 0x00, 0x00, // Reachable Time
		0x00, 0x00, 0x00, 0x00, // Retrans Timer
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Marshal = % x, want % x", got, want)
	}
}

func TestRouterAdvertisementMarshalWithOptions(t *testing.T) {
	opt := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	ra := RouterAdvertisement{Options: Options{opt}}
	got := ra.Marshal()
	if len(got) != 16+8 {
		t.Fatalf("Marshal length = %d, want %d", len(got), 16+8)
	}
	if !bytes.Equal(got[16:], opt) {
		t.Fatalf("Marshal options tail = % x, want % x", got[16:], opt)
	}
}

func TestRouterAdvertisementMarshalRouterLifetimeSaturates(t *testing.T) {
	ra := RouterAdvertisement{RouterLifetime: 100000 * time.Second}
	got := ra.Marshal()
	if got[6] != 0xff || got[7] != 0xff {
		t.Fatalf("Router Lifetime = % x, want saturated 0xffff", got[6:8])
	}
}

func TestIsRouterSolicitation(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"router solicitation", []byte{133, 0, 0, 0}, true},
		{"router advertisement", []byte{134, 0, 0, 0}, false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isRouterSolicitation(c.data); got != c.want {
				t.Errorf("isRouterSolicitation(%v) = %v, want %v", c.data, got, c.want)
			}
		})
	}
}
