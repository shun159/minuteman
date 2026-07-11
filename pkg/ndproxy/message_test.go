package ndproxy

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

func TestMarshalNeighborSolicitation(t *testing.T) {
	target := netip.MustParseAddr("2001:db8::1")
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	got := marshalNeighborSolicitation(target, mac)
	want := []byte{
		135, 0, 0x00, 0x00, // Type, Code, Checksum (kernel-computed, left zero)
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Target Address
		1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source Link-Layer Address option
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("marshalNeighborSolicitation = % x, want % x", got, want)
	}
}

func TestMarshalNeighborAdvertisement(t *testing.T) {
	target := netip.MustParseAddr("2001:db8::1")
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	cases := []struct {
		name      string
		solicited bool
		wantFlags byte
	}{
		{"solicited", true, naFlagSolicited},
		{"unsolicited", false, 0x00},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := marshalNeighborAdvertisement(target, mac, c.solicited)
			want := []byte{
				136, 0, 0x00, 0x00,
				c.wantFlags, 0x00, 0x00, 0x00,
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				2, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Target Link-Layer Address option
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("marshalNeighborAdvertisement(solicited=%v) = % x, want % x", c.solicited, got, want)
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	target := netip.MustParseAddr("2001:db8::1")
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	t.Run("valid NS", func(t *testing.T) {
		got, err := parseTarget(marshalNeighborSolicitation(target, mac), icmpTypeNeighborSolicit)
		if err != nil {
			t.Fatalf("parseTarget: %v", err)
		}
		if got != target {
			t.Fatalf("parseTarget = %v, want %v", got, target)
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		if _, err := parseTarget(marshalNeighborSolicitation(target, mac), icmpTypeNeighborAdvert); err == nil {
			t.Fatal("parseTarget with mismatched wantType: want error, got nil")
		}
	})

	t.Run("too short", func(t *testing.T) {
		if _, err := parseTarget([]byte{135, 0, 0, 0}, icmpTypeNeighborSolicit); err == nil {
			t.Fatal("parseTarget with truncated message: want error, got nil")
		}
	})
}

func TestSolicitedNodeMulticast(t *testing.T) {
	got := solicitedNodeMulticast(netip.MustParseAddr("2001:db8::1"))
	want := netip.MustParseAddr("ff02::1:ff00:1")
	if got != want {
		t.Fatalf("solicitedNodeMulticast = %v, want %v", got, want)
	}
}
