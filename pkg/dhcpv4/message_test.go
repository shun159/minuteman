package dhcpv4

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestMessageMarshalParseRoundTrip(t *testing.T) {
	mac, _ := net.ParseMAC("52:54:00:12:34:56")
	orig := &Message{
		Op:     OpBootReply,
		HType:  hardwareTypeEthernet,
		HLen:   6,
		XID:    0xdeadbeef,
		Flags:  flagBroadcast,
		YIAddr: netip.MustParseAddr("192.168.1.100"),
		SIAddr: netip.MustParseAddr("192.168.1.1"),
		CHAddr: mac,
		Options: Options{
			NewMessageType(Offer),
			NewAddr(OptServerID, netip.MustParseAddr("192.168.1.1")),
			NewSeconds(OptLeaseTime, 12*time.Hour),
			NewMTU(1460),
		},
	}

	got, err := Parse(orig.Marshal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Op != OpBootReply || got.XID != 0xdeadbeef {
		t.Errorf("op/xid = %d/%#x", got.Op, got.XID)
	}
	if !got.Broadcast() {
		t.Error("broadcast flag lost in round trip")
	}
	if got.YIAddr != orig.YIAddr || got.SIAddr != orig.SIAddr {
		t.Errorf("addrs = %v/%v, want %v/%v", got.YIAddr, got.SIAddr, orig.YIAddr, orig.SIAddr)
	}
	if got.CHAddr.String() != mac.String() {
		t.Errorf("chaddr = %v, want %v", got.CHAddr, mac)
	}
	if mt, ok := got.Options.MessageType(); !ok || mt != Offer {
		t.Errorf("message type = %v/%v, want OFFER", mt, ok)
	}
	if sid, ok := got.Options.ServerID(); !ok || sid != orig.SIAddr {
		t.Errorf("server id = %v/%v", sid, ok)
	}
}

func TestMarshalIsPaddedToMinimum(t *testing.T) {
	m := &Message{Op: OpBootReply, Options: Options{NewMessageType(ACK)}}
	if got := len(m.Marshal()); got < minMessageLen {
		t.Errorf("marshalled length = %d, want >= %d", got, minMessageLen)
	}
}

func TestParseRejectsShortAndBadCookie(t *testing.T) {
	if _, err := Parse(make([]byte, 100)); err == nil {
		t.Error("Parse of a too-short buffer: want error, got nil")
	}
	b := make([]byte, bootpFixedLen+4)
	// magic cookie left as zeros -> invalid
	if _, err := Parse(b); err == nil {
		t.Error("Parse with bad magic cookie: want error, got nil")
	}
}

func TestParseUnspecifiedAddrsAreZero(t *testing.T) {
	m := &Message{Op: OpBootRequest, Options: Options{NewMessageType(Discover)}}
	got, err := Parse(m.Marshal())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// An address field left unset marshals as 0.0.0.0, and must parse back
	// as the (valid, non-nil) unspecified IPv4 address, not an invalid Addr.
	if got.CIAddr != netip.AddrFrom4([4]byte{}) {
		t.Errorf("ciaddr = %v, want 0.0.0.0", got.CIAddr)
	}
}

func TestClientIDPrefersOptionOverChaddr(t *testing.T) {
	opts := Options{{Code: OptClientID, Data: []byte("custom-id")}}
	if got := opts.ClientID([]byte("fallback")); got != "custom-id" {
		t.Errorf("ClientID = %q, want %q", got, "custom-id")
	}
	if got := (Options{}).ClientID([]byte("fallback")); got != "fallback" {
		t.Errorf("ClientID with no option = %q, want %q", got, "fallback")
	}
}

func TestMarshalSplitsLongOptions(t *testing.T) {
	// 64 DNS servers = 256 bytes of data, past the 255-byte option length
	// field. Marshal must split it across multiple option-6 instances (RFC
	// 3396) rather than truncate the length byte and corrupt the stream.
	dns := make([]netip.Addr, 64)
	for i := range dns {
		dns[i] = netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
	}
	opts := Options{NewAddrs(OptDNSServers, dns)}
	b := opts.Marshal()

	// Walk the encoded stream: it must parse cleanly into option-6 chunks
	// that concatenate back to the full 256 bytes.
	var got int
	for i := 0; i < len(b); {
		if OptionCode(b[i]) != OptDNSServers {
			t.Fatalf("unexpected option code %d at offset %d (stream corrupted)", b[i], i)
		}
		n := int(b[i+1])
		if n > 255 || i+2+n > len(b) {
			t.Fatalf("chunk length %d at offset %d runs past the buffer", n, i)
		}
		got += n
		i += 2 + n
	}
	if got != 64*4 {
		t.Fatalf("reassembled option-6 data = %d bytes, want %d", got, 64*4)
	}
}

func TestParseOptionRejectsOverrunLength(t *testing.T) {
	// A code/length pair whose length points past the buffer must error.
	b := make([]byte, bootpFixedLen+4+3)
	copy(b[bootpFixedLen:], magicCookie[:])
	b[bootpFixedLen+4] = byte(OptDNSServers)
	b[bootpFixedLen+5] = 8 // claims 8 bytes, only 1 remains
	if _, err := Parse(b); err == nil {
		t.Error("Parse with overrun option length: want error, got nil")
	}
}
