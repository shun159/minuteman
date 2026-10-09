package dhcpv6

import (
	"context"
	"errors"
)

// The exchanges a client runs, each an Exchange with its RFC 3315 §5.5
// timing, run by an Exchanger on the interface it owns.

// InformationRequest performs a DHCPv6 stateless Information-Request/Reply
// exchange (RFC 3736), requesting requestedOptions via OPTION_ORO, and
// returns the validated Reply.
//
// Retransmission follows RFC 3315 §18.1.5/§14 exactly: an initial random
// delay up to InfMaxDelay, then retransmissions starting at InfTimeout and
// backing off (with jitter) up to a ceiling of InfMaxRT, continuing
// indefinitely (Information-Request has no maximum retransmission count or
// duration) until either a valid Reply arrives or ctx is cancelled. Callers
// that want a bounded wait should pass a context with a deadline; this
// function does not impose one itself, since indefinite retry is the
// RFC-correct (and, for a gateway with no other way to reach its AFTR,
// practically correct) behavior.
func InformationRequest(ctx context.Context, ex Exchanger, requestedOptions []uint16) (*Message, error) {
	return ex.Exchange(ctx, Exchange{
		Type:    MessageTypeInformationRequest,
		Expect:  MessageTypeReply,
		Options: Options{NewORO(requestedOptions...)},
		Timing:  Timing{InitialDelayMax: InfMaxDelay, IRT: InfTimeout, MRT: InfMaxRT},
	})
}

// Solicit performs a DHCPv6 Solicit/Advertise exchange (RFC 3315 §17,
// §18.1.1), carrying extraOptions (typically an IA_PD, RFC 3633 §9), and
// returns the first validated Advertise.
//
// Retransmission is unbounded (RFC 3315 §5.5: Solicit has no maximum
// retransmission count), matching InformationRequest's shape: it retries,
// backing off (with jitter) up to SolMaxRT, until ctx is cancelled.
//
// Per RFC 3315 §17.1.3, a client may collect Advertises from multiple
// servers over a short window and pick the most preferred; this
// implementation instead takes the first valid Advertise it sees, which is
// the common and correct behavior on a residential link with a single
// upstream delegating router.
func Solicit(ctx context.Context, ex Exchanger, extraOptions Options) (*Message, error) {
	return ex.Exchange(ctx, Exchange{
		Type:    MessageTypeSolicit,
		Expect:  MessageTypeAdvertise,
		Options: extraOptions,
		Timing:  Timing{InitialDelayMax: SolMaxDelay, IRT: SolTimeout, MRT: SolMaxRT},
	})
}

// Request performs a DHCPv6 Request/Reply exchange (RFC 3315 §18.1.1),
// carrying extraOptions (typically the server's OPTION_SERVERID echoed back
// plus the IA_PD offered in its Advertise), and returns the validated Reply.
//
// Retransmission is bounded: after ReqMaxRC unanswered attempts, this
// returns ErrExhausted. RFC 3315 §18.1.1 says a client in this state should
// restart the whole exchange at Solicit; that restart is the caller's
// responsibility, not this function's.
func Request(ctx context.Context, ex Exchanger, extraOptions Options) (*Message, error) {
	return ex.Exchange(ctx, Exchange{
		Type:    MessageTypeRequest,
		Expect:  MessageTypeReply,
		Options: extraOptions,
		Timing:  Timing{IRT: ReqTimeout, MRT: ReqMaxRT, MRC: ReqMaxRC},
	})
}

// Renew performs a DHCPv6 Renew/Reply exchange (RFC 3315 §18.1.3), carrying
// extraOptions (the server's OPTION_SERVERID plus the IA_PD being renewed),
// and returns the validated Reply.
//
// Renew has no maximum retransmission count (RFC 3315 §5.5); it retries,
// backing off up to RenMaxRT, until ctx is cancelled or a valid Reply
// arrives. Renew is only valid until the binding's T2 elapses, so callers
// should wrap ctx with a deadline at the lease's T2 rather than relying on
// this function to know about lease timing.
func Renew(ctx context.Context, ex Exchanger, extraOptions Options) (*Message, error) {
	return ex.Exchange(ctx, Exchange{
		Type:    MessageTypeRenew,
		Expect:  MessageTypeReply,
		Options: extraOptions,
		Timing:  Timing{IRT: RenTimeout, MRT: RenMaxRT},
	})
}

// Rebind performs a DHCPv6 Rebind/Reply exchange (RFC 3315 §18.1.4),
// carrying extraOptions (the IA_PD being rebound -- unlike Renew, no
// OPTION_SERVERID, since Rebind is sent when the original server hasn't
// responded and any server may answer), and returns the validated Reply.
//
// Like Renew, Rebind has no maximum retransmission count; callers should
// wrap ctx with a deadline at the shortest remaining valid lifetime across
// the binding's addresses/prefixes, since that's the point RFC 3315 says the
// client must stop using them.
func Rebind(ctx context.Context, ex Exchanger, extraOptions Options) (*Message, error) {
	return ex.Exchange(ctx, Exchange{
		Type:    MessageTypeRebind,
		Expect:  MessageTypeReply,
		Options: extraOptions,
		Timing:  Timing{IRT: RebTimeout, MRT: RebMaxRT},
	})
}

// Release performs a DHCPv6 Release/Reply exchange (RFC 3315 §18.1.6),
// carrying extraOptions (the server's OPTION_SERVERID plus the IA_PD being
// released).
//
// Release retries up to RelMaxRC times; per RFC 3315 §18.1.6, a client gives
// up on the binding locally regardless of whether the server ever
// acknowledged the Release, so ErrExhausted is treated as success here
// rather than returned to the caller.
func Release(ctx context.Context, ex Exchanger, extraOptions Options) error {
	_, err := ex.Exchange(ctx, Exchange{
		Type:    MessageTypeRelease,
		Expect:  MessageTypeReply,
		Options: extraOptions,
		Timing:  Timing{IRT: RelTimeout, MRC: RelMaxRC},
	})
	if errors.Is(err, ErrExhausted) {
		return nil
	}
	return err
}
