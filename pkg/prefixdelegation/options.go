// Package prefixdelegation implements DHCPv6 Prefix Delegation (RFC 3633):
// it uses pkg/dhcpv6's stateful Solicit/Request/Renew/Rebind/Release
// exchanges to acquire and maintain a delegated IPv6 prefix, entirely
// in-process (no external DHCP client process).
package prefixdelegation

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
)

// StatusCode is an OPTION_STATUS_CODE (RFC 3315 §22.13), carried either at
// the message level or nested inside an IA_PD to report per-binding
// failures such as NoPrefixAvail.
type StatusCode struct {
	Code    uint16
	Message string
}

// Status codes relevant to prefix delegation (RFC 3315 §24.4, RFC 3633 §9).
const (
	StatusSuccess       uint16 = 0
	StatusNoBinding     uint16 = 3
	StatusNoPrefixAvail uint16 = 6
)

// IAPrefix is an IA_PD Prefix option (RFC 3633 §10): one delegated prefix,
// with its own lifetimes, carried inside an IA_PD's options.
type IAPrefix struct {
	PreferredLifetime time.Duration
	ValidLifetime     time.Duration
	Prefix            netip.Prefix
}

// IAPD is an Identity Association for Prefix Delegation (RFC 3633 §9): an
// IAID, the renew (T1) and rebind (T2) times, and either one or more
// delegated IAPrefix options or (on failure) a StatusCode.
type IAPD struct {
	IAID       [4]byte
	T1, T2     time.Duration
	Prefixes   []IAPrefix
	StatusCode *StatusCode
}

// NewIAPDOption builds an empty OPTION_IA_PD requesting delegation under
// iaid: T1=T2=0 is the client's hint that it has no preference and the
// server should choose (RFC 3315 §22.4), and no IAPREFIX suboptions are
// included (RFC 3633 §12.1: a client with no prefix of its own omits them
// entirely when soliciting).
func NewIAPDOption(iaid [4]byte) dhcpv6.Option {
	data := make([]byte, 12)
	copy(data[0:4], iaid[:])
	// bytes 4:8 (T1) and 8:12 (T2) left as zero.
	return dhcpv6.Option{Code: dhcpv6.OptionIAPD, Data: data}
}

// iaPrefixOption encodes p as an OPTION_IAPREFIX suboption (RFC 3633 §10):
// 4-byte preferred lifetime, 4-byte valid lifetime, 1-byte prefix length,
// 16-byte prefix.
func iaPrefixOption(p IAPrefix) dhcpv6.Option {
	data := make([]byte, 25)
	binary.BigEndian.PutUint32(data[0:4], uint32(p.PreferredLifetime/time.Second))
	binary.BigEndian.PutUint32(data[4:8], uint32(p.ValidLifetime/time.Second))
	data[8] = uint8(p.Prefix.Bits())
	addr16 := p.Prefix.Addr().As16()
	copy(data[9:25], addr16[:])
	return dhcpv6.Option{Code: dhcpv6.OptionIAPrefix, Data: data}
}

// IAPDOption re-encodes iapd as an OPTION_IA_PD, including its delegated
// IAPrefix suboptions -- used to echo a lease's IA_PD back in
// Renew/Rebind/Release.
func IAPDOption(iapd IAPD) dhcpv6.Option {
	sub := make(dhcpv6.Options, 0, len(iapd.Prefixes))
	for _, p := range iapd.Prefixes {
		sub = append(sub, iaPrefixOption(p))
	}
	subBytes := sub.Marshal()

	data := make([]byte, 12+len(subBytes))
	copy(data[0:4], iapd.IAID[:])
	binary.BigEndian.PutUint32(data[4:8], uint32(iapd.T1/time.Second))
	binary.BigEndian.PutUint32(data[8:12], uint32(iapd.T2/time.Second))
	copy(data[12:], subBytes)
	return dhcpv6.Option{Code: dhcpv6.OptionIAPD, Data: data}
}

// ParseIAPD decodes opt as an OPTION_IA_PD, including its nested IAPREFIX
// and STATUS_CODE suboptions. opt.Code is not checked -- callers are
// expected to have found it via Options.Get(dhcpv6.OptionIAPD).
func ParseIAPD(opt dhcpv6.Option) (*IAPD, error) {
	if len(opt.Data) < 12 {
		return nil, fmt.Errorf("prefixdelegation: IA_PD option too short (%d bytes, want at least 12)", len(opt.Data))
	}

	iapd := &IAPD{
		T1: time.Duration(binary.BigEndian.Uint32(opt.Data[4:8])) * time.Second,
		T2: time.Duration(binary.BigEndian.Uint32(opt.Data[8:12])) * time.Second,
	}
	copy(iapd.IAID[:], opt.Data[0:4])

	subOpts, err := dhcpv6.ParseSubOptions(opt.Data[12:])
	if err != nil {
		return nil, fmt.Errorf("prefixdelegation: parsing IA_PD suboptions: %w", err)
	}

	for _, sub := range subOpts {
		switch sub.Code {
		case dhcpv6.OptionIAPrefix:
			p, err := parseIAPrefix(sub.Data)
			if err != nil {
				return nil, fmt.Errorf("prefixdelegation: parsing IAPREFIX suboption: %w", err)
			}
			iapd.Prefixes = append(iapd.Prefixes, p)
		case dhcpv6.OptionStatusCode:
			sc, err := parseStatusCode(sub.Data)
			if err != nil {
				return nil, fmt.Errorf("prefixdelegation: parsing STATUS_CODE suboption: %w", err)
			}
			iapd.StatusCode = &sc
		}
	}

	return iapd, nil
}

// parseIAPrefix decodes an OPTION_IAPREFIX payload (RFC 3633 §10): 4-byte
// preferred lifetime, 4-byte valid lifetime, 1-byte prefix length, 16-byte
// prefix, in that order. Any trailing bytes are a nested STATUS_CODE
// suboption (RFC 3633 §10, e.g. reporting a per-prefix failure) which this
// function doesn't need to interpret to build the IAPrefix itself.
func parseIAPrefix(data []byte) (IAPrefix, error) {
	const fixedLen = 4 + 4 + 1 + 16
	if len(data) < fixedLen {
		return IAPrefix{}, fmt.Errorf("prefixdelegation: IAPREFIX suboption too short (%d bytes, want at least %d)", len(data), fixedLen)
	}

	prefixLen := int(data[8])
	if prefixLen > 128 {
		return IAPrefix{}, fmt.Errorf("prefixdelegation: IAPREFIX prefix length %d exceeds 128", prefixLen)
	}
	addr, ok := netip.AddrFromSlice(data[9:25])
	if !ok {
		return IAPrefix{}, fmt.Errorf("prefixdelegation: malformed IAPREFIX address")
	}

	return IAPrefix{
		PreferredLifetime: time.Duration(binary.BigEndian.Uint32(data[0:4])) * time.Second,
		ValidLifetime:     time.Duration(binary.BigEndian.Uint32(data[4:8])) * time.Second,
		Prefix:            netip.PrefixFrom(addr, prefixLen),
	}, nil
}

// parseStatusCode decodes an OPTION_STATUS_CODE payload (RFC 3315 §22.13):
// a 2-byte status code followed by a UTF-8 status message with no
// terminator (the rest of the option data).
func parseStatusCode(data []byte) (StatusCode, error) {
	if len(data) < 2 {
		return StatusCode{}, fmt.Errorf("prefixdelegation: STATUS_CODE suboption too short (%d bytes, want at least 2)", len(data))
	}
	return StatusCode{
		Code:    binary.BigEndian.Uint16(data[0:2]),
		Message: string(data[2:]),
	}, nil
}
