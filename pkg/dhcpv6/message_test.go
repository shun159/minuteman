package dhcpv6

import "testing"

func TestMessageMarshalParseRoundTrip(t *testing.T) {
	xid, err := NewTransactionID()
	if err != nil {
		t.Fatalf("NewTransactionID: %v", err)
	}
	want := &Message{
		Type: MessageTypeInformationRequest,
		XID:  xid,
		Options: Options{
			NewORO(OptionDNSServers, OptionAFTRName),
		},
	}

	b, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	got, err := ParseMessage(b)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if got.Type != want.Type {
		t.Errorf("Type = %d, want %d", got.Type, want.Type)
	}
	if got.XID != want.XID {
		t.Errorf("XID = %x, want %x", got.XID, want.XID)
	}
	if len(got.Options) != len(want.Options) {
		t.Fatalf("got %d options, want %d", len(got.Options), len(want.Options))
	}
}

func TestParseMessageTooShort(t *testing.T) {
	if _, err := ParseMessage([]byte{0x0b, 0x00}); err == nil {
		t.Fatal("expected error for a too-short message, got nil")
	}
}
