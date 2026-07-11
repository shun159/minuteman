package aftrdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
)

// defaultRefreshInterval is RFC 4242 §2's default for stateless clients
// when the server doesn't send OPTION_INFORMATION_REFRESH_TIME.
const defaultRefreshInterval = 24 * time.Hour

// ErrNoAFTRName means the DHCPv6 server answered the Information-Request
// but its Reply carried no OPTION_AFTR_NAME -- the ISP speaks DHCPv6 but
// doesn't advertise an AFTR through it. Discover returns it alongside a
// partial (non-nil) Result so callers can feed what the Reply did carry
// (notably DNSServers) into another discovery mechanism, e.g. HB46PP.
var ErrNoAFTRName = errors.New("aftrdiscovery: reply did not include OPTION_AFTR_NAME")

// Result is the outcome of a successful AFTR discovery.
type Result struct {
	AFTRName   string
	AFTRAddr   netip.Addr
	DNSServers []netip.Addr

	// RefreshInterval is how often RFC 4242 says this information should
	// be re-fetched. It is reported here but not acted on by this
	// package -- periodic re-discovery is a caller-level policy decision.
	RefreshInterval time.Duration
}

// Discover performs a DHCPv6 Information-Request on ifaceName (RFC 3736),
// extracts the AFTR-Name (RFC 6334 OPTION_AFTR_NAME) and DNS servers (RFC
// 3646 OPTION_DNS_SERVERS) from the Reply, and resolves the AFTR-Name to an
// IPv6 address via DNS.
//
// See dhcpv6.InformationRequest for retransmission/timeout behavior: this
// blocks (retrying per RFC 3315) until it succeeds or ctx is cancelled.
//
// If the Reply carries no OPTION_AFTR_NAME, Discover returns ErrNoAFTRName
// together with a partial Result (DNSServers and RefreshInterval only) --
// the one case where both return values are non-nil.
func Discover(ctx context.Context, ifaceName string) (*Result, error) {
	reply, err := dhcpv6.InformationRequest(ctx, ifaceName, []uint16{
		dhcpv6.OptionDNSServers,
		dhcpv6.OptionAFTRName,
		dhcpv6.OptionInformationRefreshTime,
	})
	if err != nil {
		return nil, fmt.Errorf("aftrdiscovery: DHCPv6 information-request: %w", err)
	}

	var dnsServers []netip.Addr
	if dnsOpt, ok := reply.Options.Get(dhcpv6.OptionDNSServers); ok {
		if servers, err := parseDNSServers(dnsOpt.Data); err == nil {
			dnsServers = servers
		}
		// A malformed DNS servers option isn't fatal: the AFTR name may
		// still resolve via the system resolver.
	}

	refresh, ok := reply.Options.InformationRefreshTime()
	if !ok {
		refresh = defaultRefreshInterval
	}

	aftrNameOpt, ok := reply.Options.Get(dhcpv6.OptionAFTRName)
	if !ok {
		// Partial result: see ErrNoAFTRName.
		return &Result{DNSServers: dnsServers, RefreshInterval: refresh}, ErrNoAFTRName
	}
	aftrName, err := decodeDNSName(aftrNameOpt.Data)
	if err != nil {
		return nil, fmt.Errorf("aftrdiscovery: decoding OPTION_AFTR_NAME: %w", err)
	}

	aftrAddr, err := resolveAFTR(ctx, aftrName, dnsServers)
	if err != nil {
		return nil, fmt.Errorf("aftrdiscovery: %w", err)
	}

	return &Result{
		AFTRName:        aftrName,
		AFTRAddr:        aftrAddr,
		DNSServers:      dnsServers,
		RefreshInterval: refresh,
	}, nil
}
