package dhcpv6

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"time"
)

// ClientPort and ServerPort are the well-known DHCPv6 client/server UDP
// ports (RFC 3315 §5.2).
const (
	ClientPort = 546
	ServerPort = 547
)

// AllRelayAgentsAndServers is the link-scoped multicast address clients
// send to (RFC 3315 §5.1), to be given the zone of the interface.
var AllRelayAgentsAndServers = netip.MustParseAddr("ff02::1:2")

// ErrExhausted is returned by an exchange whose Timing has a maximum
// retransmission count, once that many transmissions have all gone
// unanswered. RFC 3315 §5.5 only gives a small number of exchanges (Request,
// Release) a maximum retransmission count at all -- everything else retries
// until the caller gives up.
var ErrExhausted = errors.New("dhcpv6: exchange giving up after max retransmission count")

// Timing is one RFC 3315 §5.5 exchange's retransmission parameters: the
// ceiling of the random delay before the first transmission (0: send at
// once), the initial and maximum retransmission timeouts, and the maximum
// retransmission count (0: unbounded, until the caller gives up).
type Timing struct {
	InitialDelayMax time.Duration
	IRT, MRT        time.Duration
	MRC             int
}

// Exchange is one RFC 3315 §14 message exchange: the message to send, of
// Type and carrying Options, and the reply type, Expect, that ends it.
type Exchange struct {
	Type, Expect MessageType
	Options      Options
	Timing       Timing
}

// Message is the message of x sent as transaction xid by the client
// clientID, elapsed after its first transmission: its Options between the
// client's OPTION_CLIENTID and OPTION_ELAPSED_TIME.
func (x Exchange) Message(xid TransactionID, clientID DUID, elapsed time.Duration) *Message {
	opts := make(Options, 0, len(x.Options)+2)
	opts = append(opts, NewClientIDOption(clientID))
	opts = append(opts, x.Options...)
	opts = append(opts, NewElapsedTimeOption(elapsed))
	return &Message{Type: x.Type, XID: xid, Options: opts}
}

// Answers reports whether reply ends x, sent as transaction xid by the
// client clientID: it is of the expected type and transaction, and passes
// the RFC 3315 general validation (restated for stateless service in RFC
// 3736 §4) -- it carries a Server Identifier, and if it echoes a Client
// Identifier, that is ours. A message that does not is discarded and the
// exchange goes on, per RFC 3315, rather than failing it.
func (x Exchange) Answers(reply *Message, xid TransactionID, clientID DUID) bool {
	if reply.Type != x.Expect || reply.XID != xid {
		return false
	}
	if _, ok := reply.Options.ServerID(); !ok {
		return false
	}
	if echoed, ok := reply.Options.ClientID(); ok && !bytes.Equal(echoed, clientID) {
		return false
	}
	return true
}

// Exchanger runs exchanges on one interface, one at a time: it sends x's
// message, retransmits it per x.Timing, and returns the first message that
// Answers it -- or ErrExhausted, or ctx's error once ctx is done.
type Exchanger interface {
	Exchange(ctx context.Context, x Exchange) (*Message, error)
}
