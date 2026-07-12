package dhcpv4

import (
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// OptionCode is a DHCP option code (RFC 2132).
type OptionCode uint8

// DHCP option codes this server reads or writes (RFC 2132).
const (
	OptPad           OptionCode = 0   // §3.1
	OptSubnetMask    OptionCode = 1   // §3.3
	OptRouter        OptionCode = 3   // §3.5
	OptDNSServers    OptionCode = 6   // §3.8
	OptInterfaceMTU  OptionCode = 26  // §5.1
	OptBroadcastAddr OptionCode = 28  // §5.3
	OptRequestedIP   OptionCode = 50  // §9.1
	OptLeaseTime     OptionCode = 51  // §9.2
	OptMessageType   OptionCode = 53  // §9.6
	OptServerID      OptionCode = 54  // §9.7
	OptParamReqList  OptionCode = 55  // §9.8
	OptRenewalTime   OptionCode = 58  // §9.11 (T1)
	OptRebindingTime OptionCode = 59  // §9.12 (T2)
	OptClientID      OptionCode = 61  // §9.14
	OptEnd           OptionCode = 255 // §3.2
)

// MessageType is the DHCP message type carried in OptMessageType (RFC 2131
// §3.1, RFC 2132 §9.6).
type MessageType uint8

const (
	Discover MessageType = 1
	Offer    MessageType = 2
	Request  MessageType = 3
	Decline  MessageType = 4
	ACK      MessageType = 5
	NAK      MessageType = 6
	Release  MessageType = 7
	Inform   MessageType = 8
)

func (t MessageType) String() string {
	switch t {
	case Discover:
		return "DISCOVER"
	case Offer:
		return "OFFER"
	case Request:
		return "REQUEST"
	case Decline:
		return "DECLINE"
	case ACK:
		return "ACK"
	case NAK:
		return "NAK"
	case Release:
		return "RELEASE"
	case Inform:
		return "INFORM"
	default:
		return fmt.Sprintf("MessageType(%d)", uint8(t))
	}
}

// Option is a single DHCP option (RFC 2132 §2): a 1-byte code, an implicit
// 1-byte length, and code-specific data. PAD and END never appear here;
// they're handled by the (de)serializer directly.
type Option struct {
	Code OptionCode
	Data []byte
}

// Options is an ordered sequence of DHCP options.
type Options []Option

// Get returns the first option with the given code.
func (o Options) Get(code OptionCode) (Option, bool) {
	for _, opt := range o {
		if opt.Code == code {
			return opt, true
		}
	}
	return Option{}, false
}

// Marshal encodes every option as code/length/data (RFC 2132 §2). The END
// option and any padding are appended by Message.Marshal, not here.
func (o Options) Marshal() []byte {
	var b []byte
	for _, opt := range o {
		b = append(b, byte(opt.Code), byte(len(opt.Data)))
		b = append(b, opt.Data...)
	}
	return b
}

// parseOptions decodes the options field (after the magic cookie): a
// sequence of code/length/data triples, with PAD (0) a bare byte and END
// (255) terminating. Data running past the end of b is rejected.
func parseOptions(b []byte) (Options, error) {
	var opts Options
	for i := 0; i < len(b); {
		code := OptionCode(b[i])
		switch code {
		case OptPad:
			i++
			continue
		case OptEnd:
			return opts, nil
		}
		if i+1 >= len(b) {
			return nil, fmt.Errorf("dhcpv4: truncated option %d header", code)
		}
		optLen := int(b[i+1])
		if i+2+optLen > len(b) {
			return nil, fmt.Errorf("dhcpv4: option %d length %d exceeds remaining bytes", code, optLen)
		}
		data := slices.Clone(b[i+2 : i+2+optLen])
		opts = append(opts, Option{Code: code, Data: data})
		i += 2 + optLen
	}
	// Running off the end without an END option is tolerated: the fixed
	// options field is finite and some clients omit END when the field is
	// exactly filled.
	return opts, nil
}

// --- Constructors for the options this server emits ---

// NewMessageType builds an OptMessageType option.
func NewMessageType(t MessageType) Option {
	return Option{Code: OptMessageType, Data: []byte{byte(t)}}
}

// NewAddr builds a single-address option (Router, ServerID, etc.).
func NewAddr(code OptionCode, a netip.Addr) Option {
	v := a.As4()
	return Option{Code: code, Data: v[:]}
}

// NewAddrs builds a multi-address option (DNS servers, RFC 2132 §3.8).
func NewAddrs(code OptionCode, addrs []netip.Addr) Option {
	data := make([]byte, 0, 4*len(addrs))
	for _, a := range addrs {
		v := a.As4()
		data = append(data, v[:]...)
	}
	return Option{Code: code, Data: data}
}

// NewSeconds builds a 4-byte duration option (lease/T1/T2 times), rounding
// down to whole seconds and saturating at the 32-bit maximum.
func NewSeconds(code OptionCode, d time.Duration) Option {
	secs := min(max(d/time.Second, 0), 0xffffffff)
	data := make([]byte, 4)
	putUint32(data, uint32(secs))
	return Option{Code: code, Data: data}
}

// NewMTU builds an OptInterfaceMTU option (RFC 2132 §5.1: a 2-byte MTU,
// which the spec requires be at least 68).
func NewMTU(mtu uint16) Option {
	data := make([]byte, 2)
	putUint16(data, mtu)
	return Option{Code: OptInterfaceMTU, Data: data}
}

// --- Extractors for the options this server reads ---

// MessageType extracts OptMessageType. Returns false if absent or malformed.
func (o Options) MessageType() (MessageType, bool) {
	opt, ok := o.Get(OptMessageType)
	if !ok || len(opt.Data) != 1 {
		return 0, false
	}
	return MessageType(opt.Data[0]), true
}

// RequestedIP extracts OptRequestedIP (the address a client asks for in a
// DISCOVER/REQUEST before it's bound). Returns false if absent or malformed.
func (o Options) RequestedIP() (netip.Addr, bool) {
	return o.addr(OptRequestedIP)
}

// ServerID extracts OptServerID (which server a REQUEST is directed at, so a
// server not selected by the client stays quiet). Returns false if absent.
func (o Options) ServerID() (netip.Addr, bool) {
	return o.addr(OptServerID)
}

func (o Options) addr(code OptionCode) (netip.Addr, bool) {
	opt, ok := o.Get(code)
	if !ok || len(opt.Data) != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(opt.Data)), true
}

// ClientID extracts OptClientID if present, falling back to the chaddr-based
// identity the caller passes as fallback (RFC 2131 §4.2: a client is keyed
// by its client-identifier if it sends one, else by chaddr). The returned
// value is an opaque map key, not meant to be interpreted further.
func (o Options) ClientID(fallback []byte) string {
	if opt, ok := o.Get(OptClientID); ok && len(opt.Data) > 0 {
		return string(opt.Data)
	}
	return string(fallback)
}
