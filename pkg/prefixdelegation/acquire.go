package prefixdelegation

import (
	"context"
	"fmt"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
)

// usableIAPD extracts and validates an OPTION_IA_PD from msg: it must be
// present, decode cleanly, report no failure status, and carry at least one
// delegated prefix. Returns an error describing what's wrong if not -- the
// caller treats any such error as "discard and retry", per RFC 3315's
// general validation rule (never fail the whole exchange over one bad
// message).
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
	if len(iapd.Prefixes) == 0 {
		return nil, nil, fmt.Errorf("prefixdelegation: IA_PD carries no delegated prefixes")
	}
	return iapd, serverID, nil
}

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
		advertise, err := dhcpv6.Solicit(ctx, ifaceName, dhcpv6.Options{NewIAPDOption(clientIAID)})
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

		return &Lease{
			ServerID:   serverID,
			Prefixes:   granted.Prefixes,
			T1:         granted.T1,
			T2:         granted.T2,
			AcquiredAt: time.Now(),
		}, nil
	}
}
