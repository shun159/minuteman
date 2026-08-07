package prefixdelegation

import (
	"context"
	"fmt"
	"slices"

	"github.com/shun159/miniteman/pkg/dhcpv6"
)

// usableIAPD extracts and validates an OPTION_IA_PD from msg: it must be
// present, decode cleanly, report no failure status, carry at least one
// delegated prefix left after §21.22's preferred-beyond-valid ones are
// dropped, and not carry the T1 > T2 > 0 combination RFC 9915 §21.21
// tells a client to discard the option over. Returns an error
// describing what's wrong if not -- the caller treats any such error as
// "discard and retry", per RFC 3315's general validation rule (never fail
// the whole exchange over one bad message).
func usableIAPD(msg *dhcpv6.Message) (*IAPD, dhcpv6.DUID, error) {
	serverID, ok := msg.Options.ServerID()
	if !ok {
		// Unreachable in practice: pkg/dhcpv6's validateServerMessage
		// already requires OPTION_SERVERID before returning this message.
		return nil, nil, fmt.Errorf("prefixdelegation: message missing OPTION_SERVERID")
	}

	iaOpt, ok := msg.Options.Get(dhcpv6.OptionIAPD)
	if !ok {
		return nil, nil, fmt.Errorf("prefixdelegation: message missing OPTION_IA_PD")
	}
	iapd, err := ParseIAPD(iaOpt)
	if err != nil {
		return nil, nil, err
	}
	if iapd.StatusCode != nil && iapd.StatusCode.Code != StatusSuccess {
		return nil, nil, fmt.Errorf("prefixdelegation: server returned status %d (%s)", iapd.StatusCode.Code, iapd.StatusCode.Message)
	}
	// RFC 9915 §21.22: "The client MUST discard any prefixes for which the
	// preferred lifetime is greater than the valid lifetime." Dropping
	// them individually (rather than the whole IA_PD) is what the MUST
	// says, and it keeps the lease timers derived from lifetimes that
	// make sense -- see effectiveTimers.
	iapd.Prefixes = slices.DeleteFunc(iapd.Prefixes, func(p IAPrefix) bool {
		return p.PreferredLifetime > p.ValidLifetime
	})
	if len(iapd.Prefixes) == 0 {
		return nil, nil, fmt.Errorf("prefixdelegation: IA_PD carries no usable delegated prefixes")
	}
	// RFC 9915 §21.21: an IA_PD with T1 greater than T2, both non-zero,
	// is invalid -- the client discards the option and processes the rest
	// of the message as though the server hadn't sent it. Discarding the
	// only IA_PD in play leaves nothing usable, so it becomes a retry.
	if iapd.T2 > 0 && iapd.T1 > iapd.T2 {
		return nil, nil, fmt.Errorf("prefixdelegation: IA_PD has T1 (%v) greater than T2 (%v)", iapd.T1, iapd.T2)
	}
	return iapd, serverID, nil
}

// requestedOptions is the OPTION_ORO this client sends with its Solicit and
// Request (RFC 3315 §21.7). An IA_PD is carried as its own option and needs
// no ORO entry; what does is OPTION_DNS_SERVERS, because on a network that
// doesn't answer Information-Request the stateful exchange is the only place
// a resolver can be learned from DHCPv6 at all -- and minuteman's HB46PP
// discovery fallback needs one to look anything up. Asking costs a handful of
// bytes on two messages and a server free to ignore it.
var requestedOptions = dhcpv6.NewORO(dhcpv6.OptionDNSServers)

// Acquire performs a full Solicit/Advertise/Request/Reply exchange (RFC
// 3315 §17-18, RFC 3633) on ifaceName to obtain a delegated prefix, and
// returns the resulting Lease.
//
// Blocks (retrying per RFC 3315 timing) until it succeeds or ctx is
// cancelled -- same rationale as pkg/aftrdiscovery.Discover: there's no LAN
// prefix to assign without one, so indefinite retry is correct. A Reply
// carrying more than one delegated prefix keeps all of them in
// Lease.Prefixes; callers that only use one should use Prefixes[0].
func Acquire(ctx context.Context, ifaceName string) (*Lease, error) {
	for {
		solOptions := dhcpv6.Options{NewIAPDOption(clientIAID), requestedOptions}
		advertise, err := dhcpv6.Solicit(ctx, ifaceName, solOptions)
		if err != nil {
			return nil, fmt.Errorf("prefixdelegation: soliciting on %s: %w", ifaceName, err)
		}

		offered, serverID, err := usableIAPD(advertise)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			continue // discard and re-Solicit, per RFC 3315's general validation rule
		}

		reqOptions := dhcpv6.Options{
			{Code: dhcpv6.OptionServerID, Data: serverID},
			IAPDOption(*offered),
			requestedOptions,
		}
		reply, err := dhcpv6.Request(ctx, ifaceName, reqOptions)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			continue // ReqMaxRC exhausted: RFC 3315 §18.1.1 says restart at Solicit
		}

		granted, _, err := usableIAPD(reply)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			continue
		}

		// A DNS servers option this client asked for but can't parse is
		// dropped, not fatal: it has no bearing on the delegation itself,
		// which is what the exchange is for.
		dnsServers, _, err := reply.Options.DNSServers()
		if err != nil {
			dnsServers = nil
		}

		return newLease(serverID, granted, dnsServers), nil
	}
}
