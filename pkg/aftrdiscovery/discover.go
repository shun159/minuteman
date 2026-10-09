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

// ErrNoReply means nothing answered the Information-Request within the
// replyTimeout the caller gave Discover -- most likely a network that does
// not implement stateless DHCPv6 at all, as opposed to ErrNoAFTRName's
// network that does but has no AFTR to name.
//
// Unlike ErrNoAFTRName there is no partial Result to return with it: without
// a Reply nothing was learned, not even DNS servers, so a caller falling
// forward to another discovery mechanism has to source those elsewhere (in
// minuteman's case, from the DHCPv6-PD exchange).
//
// Two access tiers of the NTT East FLET'S IPoE spec state outright that the
// network does not support Information-Request (光クロス §4.4.2.1.2 and
// 光25G §2.4.1.1.2 of 第三分冊), which is why this is a named outcome and not
// just a timeout: on those the unbounded RFC 3315 retry would otherwise be an
// indefinite hang rather than a discovery failure.
var ErrNoReply = errors.New("aftrdiscovery: no reply to the DHCPv6 information-request")

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

// Discover performs a DHCPv6 Information-Request through ex (RFC 3736),
// extracts the AFTR-Name (RFC 6334 OPTION_AFTR_NAME) and DNS servers (RFC
// 3646 OPTION_DNS_SERVERS) from the Reply, and resolves the AFTR-Name to an
// IPv6 address via DNS.
//
// replyTimeout bounds how long to wait for a Reply. It covers only the
// Information-Request exchange, not the AFTR-name DNS resolution that
// follows, so a timeout unambiguously means "nothing answered" and is
// reported as ErrNoReply. Zero or negative keeps dhcpv6.InformationRequest's
// own behavior: retry per RFC 3315 §18.1.5 (which sets no maximum
// retransmission count or duration) until a Reply arrives or ctx is
// cancelled. That is the RFC-correct default, and the right one wherever the
// network is known to answer eventually; a bound is a caller's policy for
// networks that never will.
//
// If the Reply carries no OPTION_AFTR_NAME, Discover returns ErrNoAFTRName
// together with a partial Result (DNSServers and RefreshInterval only) --
// the one case where both return values are non-nil.
func Discover(ctx context.Context, ex dhcpv6.Exchanger, replyTimeout time.Duration) (*Result, error) {
	irCtx := ctx
	if replyTimeout > 0 {
		var cancel context.CancelFunc
		irCtx, cancel = context.WithTimeout(ctx, replyTimeout)
		defer cancel()
	}

	reply, err := dhcpv6.InformationRequest(irCtx, ex, []uint16{
		dhcpv6.OptionDNSServers,
		dhcpv6.OptionAFTRName,
		dhcpv6.OptionInformationRefreshTime,
	})
	if err != nil {
		// Distinguish our own bound expiring from the caller cancelling:
		// only the former is ErrNoReply. ctx.Err() is what tells them
		// apart, since irCtx's deadline surfaces as the same
		// context.DeadlineExceeded either way.
		if replyTimeout > 0 && errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return nil, fmt.Errorf("%w within %v", ErrNoReply, replyTimeout)
		}
		return nil, fmt.Errorf("aftrdiscovery: DHCPv6 information-request: %w", err)
	}

	// A malformed DNS servers option isn't fatal: the AFTR name may still
	// resolve via the system resolver.
	dnsServers, _, err := reply.Options.DNSServers()
	if err != nil {
		dnsServers = nil
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
