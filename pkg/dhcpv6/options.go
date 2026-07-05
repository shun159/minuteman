package dhcpv6

import (
	"encoding/binary"
	"fmt"
	"time"
)

// DHCPv6 option codes used by this client.
const (
	OptionClientID               uint16 = 1  // RFC 3315 §21.2
	OptionServerID               uint16 = 2  // RFC 3315 §21.3
	OptionIAPD                   uint16 = 25 // RFC 3633 §9
	OptionIAPrefix               uint16 = 26 // RFC 3633 §10
	OptionORO                    uint16 = 6  // RFC 3315 §21.7 (Option Request Option)
	OptionElapsedTime            uint16 = 8  // RFC 3315 §21.9
	OptionStatusCode             uint16 = 13 // RFC 3315 §22.13
	OptionDNSServers             uint16 = 23 // RFC 3646 §3
	OptionAFTRName               uint16 = 64 // RFC 6334 §4
	OptionInformationRefreshTime uint16 = 32 // RFC 4242 §2
)

// maxElapsedTime is the saturating value for OPTION_ELAPSED_TIME (RFC 3315
// §22.9: "the value is set to 0xffff if the actual elapsed time exceeds the
// largest time value that can be represented").
const maxElapsedTime = 0xffff

// Option is a single DHCPv6 option (RFC 3315 §22.1): a 2-byte code, an
// implicit 2-byte length, and code-specific data.
type Option struct {
	Code uint16
	Data []byte
}

// Options is an ordered sequence of DHCPv6 options.
type Options []Option

// Get returns the first option with the given code.
func (o Options) Get(code uint16) (Option, bool) {
	for _, opt := range o {
		if opt.Code == code {
			return opt, true
		}
	}
	return Option{}, false
}

// Marshal encodes every option back-to-back per RFC 3315 §22.1.
func (o Options) Marshal() []byte {
	n := 0
	for _, opt := range o {
		n += 4 + len(opt.Data)
	}
	b := make([]byte, n)
	off := 0
	for _, opt := range o {
		binary.BigEndian.PutUint16(b[off:], opt.Code)
		binary.BigEndian.PutUint16(b[off+2:], uint16(len(opt.Data)))
		copy(b[off+4:], opt.Data)
		off += 4 + len(opt.Data)
	}
	return b
}

// ParseSubOptions decodes a back-to-back sequence of options embedded
// inside another option's data (e.g. IA_PD's nested IAPREFIX/STATUS_CODE
// suboptions, RFC 3633 §9) -- the format is byte-for-byte identical to
// top-level message options (RFC 3315 §22.1), so this simply re-exports
// parseOptions for packages built on top of pkg/dhcpv6 that need to decode
// their own nested option types.
func ParseSubOptions(b []byte) (Options, error) {
	return parseOptions(b)
}

// parseOptions decodes a back-to-back sequence of options, rejecting any
// option whose declared length runs past the end of b.
func parseOptions(b []byte) (Options, error) {
	var opts Options
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("dhcpv6: truncated option header (%d bytes left)", len(b))
		}
		code := binary.BigEndian.Uint16(b)
		optLen := int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+optLen {
			return nil, fmt.Errorf("dhcpv6: option %d length %d exceeds remaining %d bytes", code, optLen, len(b)-4)
		}
		data := make([]byte, optLen)
		copy(data, b[4:4+optLen])
		opts = append(opts, Option{Code: code, Data: data})
		b = b[4+optLen:]
	}
	return opts, nil
}

// NewClientIDOption builds an OPTION_CLIENTID from a DUID.
func NewClientIDOption(d DUID) Option {
	return Option{Code: OptionClientID, Data: append([]byte(nil), d...)}
}

// NewORO builds an OPTION_ORO (Option Request Option) listing codes.
func NewORO(codes ...uint16) Option {
	data := make([]byte, 2*len(codes))
	for i, c := range codes {
		binary.BigEndian.PutUint16(data[2*i:], c)
	}
	return Option{Code: OptionORO, Data: data}
}

// NewElapsedTimeOption builds an OPTION_ELAPSED_TIME representing the time
// since the client's first transmission of this message exchange, in
// hundredths of a second, saturating at 0xffff (RFC 3315 §22.9).
func NewElapsedTimeOption(sinceFirstSend time.Duration) Option {
	centiseconds := sinceFirstSend / (10 * time.Millisecond)
	if centiseconds > maxElapsedTime {
		centiseconds = maxElapsedTime
	}
	if centiseconds < 0 {
		centiseconds = 0
	}
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, uint16(centiseconds))
	return Option{Code: OptionElapsedTime, Data: data}
}

// ClientID extracts OPTION_CLIENTID, if present.
func (o Options) ClientID() (DUID, bool) {
	opt, ok := o.Get(OptionClientID)
	if !ok {
		return nil, false
	}
	return DUID(opt.Data), true
}

// ServerID extracts OPTION_SERVERID, if present.
func (o Options) ServerID() (DUID, bool) {
	opt, ok := o.Get(OptionServerID)
	if !ok {
		return nil, false
	}
	return DUID(opt.Data), true
}

// InformationRefreshTime extracts OPTION_INFORMATION_REFRESH_TIME (RFC 4242
// §2: an unsigned 32-bit number of seconds). Returns false if absent.
func (o Options) InformationRefreshTime() (time.Duration, bool) {
	opt, ok := o.Get(OptionInformationRefreshTime)
	if !ok || len(opt.Data) != 4 {
		return 0, false
	}
	return time.Duration(binary.BigEndian.Uint32(opt.Data)) * time.Second, true
}
