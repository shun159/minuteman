package dhcpv4

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

func TestBuildFrameRoundTripsAndChecksums(t *testing.T) {
	src := netip.MustParseAddr("192.168.1.1")
	dst := netip.MustParseAddr("192.168.1.100")
	payload := []byte("this is a stand-in DHCP payload of some length")

	frame := buildFrame(src, dst, payload)

	// The payload follows the 20-byte IPv4 + 8-byte UDP headers verbatim.
	// (parseUDPToBOOTP is the receive path, which matches the server port 67;
	// buildFrame is the send path, replying to the client port 68, so they're
	// not inverses -- verify the framing directly here.)
	if got := frame[28:]; !bytes.Equal(got, payload) {
		t.Fatalf("framed payload = %q, want %q", got, payload)
	}

	// A valid IPv4 header checksums to zero when re-summed including the
	// stored checksum (RFC 1071).
	if c := checksum(frame[:20]); c != 0 {
		t.Errorf("IPv4 header checksum invalid: re-sum = %#04x, want 0", c)
	}
	// Likewise the UDP checksum over the pseudo-header + UDP.
	s4, d4 := src.As4(), dst.As4()
	if c := udpChecksum(s4, d4, frame[20:]); c != 0 {
		t.Errorf("UDP checksum invalid: re-sum = %#04x, want 0", c)
	}

	// Sanity on the framed ports and addresses.
	if frame[9] != 17 {
		t.Errorf("IP protocol = %d, want 17 (UDP)", frame[9])
	}
	if getUint16(frame[20:]) != bootpServerPort || getUint16(frame[22:]) != bootpClientPort {
		t.Errorf("UDP ports = %d->%d, want %d->%d",
			getUint16(frame[20:]), getUint16(frame[22:]), bootpServerPort, bootpClientPort)
	}
}

func TestParseUDPToBOOTPTrimsPaddingAndChecksPort(t *testing.T) {
	// A minimal client->server (dport 67) IPv4/UDP frame carrying "hello",
	// then 10 bytes of Ethernet padding the UDP length field must exclude.
	payload := []byte("hello")
	udpLen := 8 + len(payload)
	frame := make([]byte, 20+udpLen+10)
	frame[0] = 0x45
	frame[9] = 17                          // UDP
	putUint16(frame[20:], bootpClientPort) // src 68
	putUint16(frame[22:], bootpServerPort) // dst 67
	putUint16(frame[24:], uint16(udpLen))  // UDP length excludes the padding
	copy(frame[28:], payload)

	got, ok := parseUDPToBOOTP(frame)
	if !ok {
		t.Fatal("parseUDPToBOOTP rejected a valid request frame")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q (padding not trimmed?)", got, payload)
	}

	// A frame to the wrong UDP port must be rejected.
	putUint16(frame[22:], 12345)
	if _, ok := parseUDPToBOOTP(frame); ok {
		t.Error("parseUDPToBOOTP accepted a frame not destined for port 67")
	}
}

func TestDestinationBroadcastVsUnicast(t *testing.T) {
	mac, _ := net.ParseMAC("52:54:00:11:22:33")
	bcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	t.Run("broadcast flag", func(t *testing.T) {
		reply := &Message{Flags: flagBroadcast, YIAddr: netip.MustParseAddr("192.168.1.5"), CHAddr: mac}
		ip, hw := destination(reply)
		if ip != netip.MustParseAddr("255.255.255.255") || !bytes.Equal(hw, bcastMAC) {
			t.Fatalf("broadcast reply -> %v/%v, want 255.255.255.255/ff:ff:...", ip, hw)
		}
	})

	t.Run("unicast to yiaddr", func(t *testing.T) {
		reply := &Message{YIAddr: netip.MustParseAddr("192.168.1.5"), CHAddr: mac}
		ip, hw := destination(reply)
		if ip != netip.MustParseAddr("192.168.1.5") || !bytes.Equal(hw, mac) {
			t.Fatalf("unicast reply -> %v/%v, want 192.168.1.5/client MAC", ip, hw)
		}
	})

	t.Run("inform ack falls back to ciaddr", func(t *testing.T) {
		reply := &Message{CIAddr: netip.MustParseAddr("192.168.1.200"), CHAddr: mac}
		ip, _ := destination(reply)
		if ip != netip.MustParseAddr("192.168.1.200") {
			t.Fatalf("inform reply dst = %v, want the client's ciaddr 192.168.1.200", ip)
		}
	})
}
