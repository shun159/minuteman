package dhcpv6

import (
	"crypto/rand"
	"fmt"
)

// MessageType is a DHCPv6 message type (RFC 3315 §5.3).
type MessageType uint8

const (
	MessageTypeSolicit            MessageType = 1
	MessageTypeAdvertise          MessageType = 2
	MessageTypeRequest            MessageType = 3
	MessageTypeConfirm            MessageType = 4
	MessageTypeRenew              MessageType = 5
	MessageTypeRebind             MessageType = 6
	MessageTypeReply              MessageType = 7
	MessageTypeRelease            MessageType = 8
	MessageTypeDecline            MessageType = 9
	MessageTypeReconfigure        MessageType = 10
	MessageTypeInformationRequest MessageType = 11
	MessageTypeRelayForw          MessageType = 12
	MessageTypeRelayRepl          MessageType = 13
)

// TransactionID is the 3-byte transaction identifier used to correlate a
// client message with its Reply (RFC 3315 §6).
type TransactionID [3]byte

// NewTransactionID generates a random transaction ID. RFC 3315 only
// requires it be unlikely to collide with other clients' in-flight
// exchanges, not cryptographic quality; crypto/rand is used here simply
// because it's always available without seeding.
func NewTransactionID() (TransactionID, error) {
	var xid TransactionID
	if _, err := rand.Read(xid[:]); err != nil {
		return TransactionID{}, fmt.Errorf("generating transaction ID: %w", err)
	}
	return xid, nil
}

// Message is a DHCPv6 client/server message (RFC 3315 §6): a 1-byte type,
// a 3-byte transaction ID, and a sequence of options.
type Message struct {
	Type    MessageType
	XID     TransactionID
	Options Options
}

// MarshalBinary encodes m per RFC 3315 §6.
func (m *Message) MarshalBinary() ([]byte, error) {
	optBytes := m.Options.Marshal()
	b := make([]byte, 4+len(optBytes))
	b[0] = byte(m.Type)
	copy(b[1:4], m.XID[:])
	copy(b[4:], optBytes)
	return b, nil
}

// ParseMessage decodes a DHCPv6 message per RFC 3315 §6.
func ParseMessage(b []byte) (*Message, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("dhcpv6: message too short (%d bytes)", len(b))
	}
	opts, err := parseOptions(b[4:])
	if err != nil {
		return nil, fmt.Errorf("dhcpv6: parsing options: %w", err)
	}
	m := &Message{Type: MessageType(b[0]), Options: opts}
	copy(m.XID[:], b[1:4])
	return m, nil
}
