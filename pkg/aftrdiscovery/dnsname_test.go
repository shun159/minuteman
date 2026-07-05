package aftrdiscovery

import (
	"bytes"
	"strings"
	"testing"
)

// encodeName builds the RFC 1035 wire-format encoding of name for test
// fixtures (mirrors what a compliant DHCPv6 server would send).
func encodeName(t *testing.T, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, label := range strings.Split(name, ".") {
		if len(label) > 255 {
			t.Fatalf("label %q too long for a test fixture", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	return buf.Bytes()
}

func TestDecodeDNSNameValid(t *testing.T) {
	const name = "aftr.dslite.example.com"
	got, err := decodeDNSName(encodeName(t, name))
	if err != nil {
		t.Fatalf("decodeDNSName: %v", err)
	}
	if got != name {
		t.Errorf("decodeDNSName() = %q, want %q", got, name)
	}
}

func TestDecodeDNSNameRoot(t *testing.T) {
	got, err := decodeDNSName([]byte{0x00})
	if err != nil {
		t.Fatalf("decodeDNSName: %v", err)
	}
	if got != "" {
		t.Errorf("decodeDNSName(root) = %q, want empty string", got)
	}
}

func TestDecodeDNSNameInvalid(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"compression pointer", []byte{0xC0, 0x0C}},
		{"reserved prefix 01", []byte{0x40, 0x00}},
		{"reserved prefix 10", []byte{0x80, 0x00}},
		{"truncated label", []byte{0x04, 'a', 'f', 't'}},
		{"missing terminator", []byte{0x04, 'a', 'f', 't', 'r'}},
		{"trailing bytes after terminator", append(encodeName(t, "aftr"), 0xFF)},
		{"empty buffer", []byte{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := decodeDNSName(c.data); err == nil {
				t.Fatalf("decodeDNSName(%x): expected error, got nil", c.data)
			}
		})
	}
}

func TestDecodeDNSNameTooLong(t *testing.T) {
	// One label of 63 octets (the RFC 1035 per-label max) repeated enough
	// times to push the total name length over 255 octets.
	label := strings.Repeat("a", 63)
	name := strings.Join([]string{label, label, label, label, label}, ".")
	if _, err := decodeDNSName(encodeName(t, name)); err == nil {
		t.Fatal("expected error for an over-length name, got nil")
	}
}
