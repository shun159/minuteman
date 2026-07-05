package routeradvert

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNewPrefixInformation(t *testing.T) {
	got := NewPrefixInformation(PrefixInformation{
		Prefix:            netip.MustParsePrefix("2001:db8:1:2::/64"),
		OnLink:            true,
		Autonomous:        true,
		ValidLifetime:     86400 * time.Second,
		PreferredLifetime: 14400 * time.Second,
	})

	want := []byte{
		3, 4, // Type=3, Length=4 (32 bytes / 8)
		64,                     // Prefix Length
		0xc0,                   // L=1, A=1, Reserved1=0
		0x00, 0x01, 0x51, 0x80, // Valid Lifetime = 86400
		0x00, 0x00, 0x38, 0x40, // Preferred Lifetime = 14400
		0x00, 0x00, 0x00, 0x00, // Reserved2
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("NewPrefixInformation = % x, want % x", got, want)
	}
}

func TestNewPrefixInformationFlags(t *testing.T) {
	cases := []struct {
		name            string
		onLink, autonom bool
		wantFlagsByte   byte
	}{
		{"neither", false, false, 0x00},
		{"on-link only", true, false, 0x80},
		{"autonomous only", false, true, 0x40},
		{"both", true, true, 0xc0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opt := NewPrefixInformation(PrefixInformation{
				Prefix:     netip.MustParsePrefix("2001:db8::/64"),
				OnLink:     c.onLink,
				Autonomous: c.autonom,
			})
			if opt[3] != c.wantFlagsByte {
				t.Errorf("flags byte = %#x, want %#x", opt[3], c.wantFlagsByte)
			}
		})
	}
}

func TestNewSourceLinkLayerAddress(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	got := NewSourceLinkLayerAddress(mac)
	want := []byte{1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	if !bytes.Equal(got, want) {
		t.Fatalf("NewSourceLinkLayerAddress = % x, want % x", got, want)
	}
}

func TestOptionsMarshal(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	opts := Options{
		NewPrefixInformation(PrefixInformation{Prefix: netip.MustParsePrefix("2001:db8::/64")}),
		NewSourceLinkLayerAddress(mac),
	}
	got := opts.Marshal()
	if len(got) != 32+8 {
		t.Fatalf("Marshal length = %d, want %d", len(got), 32+8)
	}
	if !bytes.Equal(got[:32], opts[0]) || !bytes.Equal(got[32:], opts[1]) {
		t.Fatalf("Marshal did not concatenate options back-to-back: % x", got)
	}
}
