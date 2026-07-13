package dhcpv6

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// errExchangeExhausted is returned by runExchange when cfg.mrc is non-zero
// and that many retransmissions have all gone unanswered. RFC 3315 §5.5
// only gives a small number of exchanges (Request, Release) a maximum
// retransmission count at all -- everything else retries forever (bounded
// only by ctx), so this is only ever seen from those.
var errExchangeExhausted = errors.New("dhcpv6: exchange giving up after max retransmission count")

// exchangeConfig holds one RFC 3315 §5.5 exchange's retransmission timing:
// the initial delay ceiling (0 = send immediately), the initial/maximum
// retransmission timeouts, and an optional maximum retransmission count (0 =
// unbounded, rely on ctx to end the loop).
type exchangeConfig struct {
	initialDelayMax time.Duration
	irt, mrt        time.Duration
	mrc             int
}

// runExchange drives one RFC 3315 §14 retransmission loop: an initial
// jittered delay (per cfg.initialDelayMax), then repeated send/wait cycles
// via newMsg/sendAndWait with RT backing off from cfg.irt up to cfg.mrt,
// validating each reply that arrives with validate and discarding (per RFC
// 3315: not failing the exchange on) any that doesn't pass. It returns the
// first validated reply, errExchangeExhausted once cfg.mrc retransmissions
// have gone unanswered (if cfg.mrc != 0), or ctx's error if cancelled first.
func runExchange(ctx context.Context, conn *net.UDPConn, dst *net.UDPAddr,
	newMsg func(elapsed time.Duration) *Message, expectedType MessageType,
	cfg exchangeConfig, validate func(*Message) error) (*Message, error) {
	if err := sleepCtx(ctx, randDelay(cfg.initialDelayMax)); err != nil {
		return nil, err
	}

	firstSend := time.Now()
	rt := firstRT(cfg.irt)
	for attempt := 1; ; attempt++ {
		msg := newMsg(time.Since(firstSend))

		reply, err := sendAndWait(ctx, conn, dst, msg, rt, expectedType)
		if err != nil {
			return nil, err
		}
		if reply != nil {
			if err := validate(reply); err == nil {
				return reply, nil
			}
			// Invalid reply (e.g. no ServerID, or a ClientID echo that
			// doesn't match ours): RFC 3315 says discard and keep
			// retrying, not fail the exchange.
		}

		if cfg.mrc != 0 && attempt >= cfg.mrc {
			return nil, errExchangeExhausted
		}
		rt = nextRT(rt, cfg.mrt)
	}
}

// InformationRequest performs a DHCPv6 stateless Information-Request/Reply
// exchange (RFC 3736) on ifaceName, requesting requestedOptions via
// OPTION_ORO, and returns the validated Reply message.
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
func InformationRequest(ctx context.Context, ifaceName string, requestedOptions []uint16) (*Message, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("looking up interface %s: %w", ifaceName, err)
	}
	duid, err := DUIDLLFromInterface(iface)
	if err != nil {
		return nil, fmt.Errorf("building client DUID: %w", err)
	}

	// Serialize with any other DHCPv6 exchange on this interface: they share
	// the same :546 bind (see lockWAN). Released after conn.Close (deferred
	// LIFO) so the next exchange binds cleanly.
	release, err := lockWAN(ctx, ifaceName)
	if err != nil {
		return nil, err
	}
	defer release()

	conn, err := bindWAN(iface)
	if err != nil {
		return nil, fmt.Errorf("binding DHCPv6 client socket: %w", err)
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.ParseIP(allDHCPRelayAgentsAndServers), Port: serverPort, Zone: ifaceName}

	xid, err := NewTransactionID()
	if err != nil {
		return nil, err
	}
	clientIDOpt := NewClientIDOption(duid)
	oroOpt := NewORO(requestedOptions...)

	newMsg := func(elapsed time.Duration) *Message {
		return &Message{
			Type: MessageTypeInformationRequest,
			XID:  xid,
			Options: Options{
				clientIDOpt,
				oroOpt,
				NewElapsedTimeOption(elapsed),
			},
		}
	}

	cfg := exchangeConfig{initialDelayMax: InfMaxDelay, irt: InfTimeout, mrt: InfMaxRT}
	return runExchange(ctx, conn, dst, newMsg, MessageTypeReply, cfg, func(reply *Message) error {
		return validateServerMessage(reply, duid)
	})
}

// validateServerMessage checks an Advertise or Reply against the RFC 3315
// general validation rule (restated for stateless service in RFC 3736 §4):
// the message must carry a Server Identifier, and if the client sent a
// Client Identifier, the message's echoed one (if present) must match.
func validateServerMessage(reply *Message, sentClientID DUID) error {
	if _, ok := reply.Options.ServerID(); !ok {
		return fmt.Errorf("dhcpv6: message missing OPTION_SERVERID")
	}
	if echoed, ok := reply.Options.ClientID(); ok && !bytes.Equal(echoed, sentClientID) {
		return fmt.Errorf("dhcpv6: message's OPTION_CLIENTID does not match ours")
	}
	return nil
}

// doExchange is the shared setup for every stateful (Solicit/Request/Renew/
// Rebind/Release) exchange: it looks up ifaceName, derives the client DUID,
// binds the DHCPv6 client socket, and drives one runExchange loop sending
// msgType messages carrying extraOptions (with the client's own
// OPTION_CLIENTID prepended) and expecting expectedType back.
func doExchange(ctx context.Context, ifaceName string, msgType, expectedType MessageType,
	extraOptions Options, cfg exchangeConfig) (*Message, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("looking up interface %s: %w", ifaceName, err)
	}
	duid, err := DUIDLLFromInterface(iface)
	if err != nil {
		return nil, fmt.Errorf("building client DUID: %w", err)
	}

	// Serialize with any other DHCPv6 exchange on this interface (see lockWAN);
	// released after conn.Close via LIFO defers.
	release, err := lockWAN(ctx, ifaceName)
	if err != nil {
		return nil, err
	}
	defer release()

	conn, err := bindWAN(iface)
	if err != nil {
		return nil, fmt.Errorf("binding DHCPv6 client socket: %w", err)
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.ParseIP(allDHCPRelayAgentsAndServers), Port: serverPort, Zone: ifaceName}

	xid, err := NewTransactionID()
	if err != nil {
		return nil, err
	}
	clientIDOpt := NewClientIDOption(duid)

	newMsg := func(elapsed time.Duration) *Message {
		opts := make(Options, 0, len(extraOptions)+2)
		opts = append(opts, clientIDOpt)
		opts = append(opts, extraOptions...)
		opts = append(opts, NewElapsedTimeOption(elapsed))
		return &Message{Type: msgType, XID: xid, Options: opts}
	}

	return runExchange(ctx, conn, dst, newMsg, expectedType, cfg, func(reply *Message) error {
		return validateServerMessage(reply, duid)
	})
}

// Solicit performs a DHCPv6 Solicit/Advertise exchange (RFC 3315 §17,
// §18.1.1) on ifaceName, carrying extraOptions (typically an IA_PD, RFC
// 3633 §9), and returns the first validated Advertise.
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
func Solicit(ctx context.Context, ifaceName string, extraOptions Options) (*Message, error) {
	cfg := exchangeConfig{initialDelayMax: SolMaxDelay, irt: SolTimeout, mrt: SolMaxRT}
	return doExchange(ctx, ifaceName, MessageTypeSolicit, MessageTypeAdvertise, extraOptions, cfg)
}

// Request performs a DHCPv6 Request/Reply exchange (RFC 3315 §18.1.1) on
// ifaceName, carrying extraOptions (typically the server's OPTION_SERVERID
// echoed back plus the IA_PD offered in its Advertise), and returns the
// validated Reply.
//
// Retransmission is bounded: after ReqMaxRC unanswered attempts, this
// returns errExchangeExhausted. RFC 3315 §18.1.1 says a client in this
// state should restart the whole exchange at Solicit; that restart is the
// caller's responsibility, not this function's.
func Request(ctx context.Context, ifaceName string, extraOptions Options) (*Message, error) {
	cfg := exchangeConfig{irt: ReqTimeout, mrt: ReqMaxRT, mrc: ReqMaxRC}
	return doExchange(ctx, ifaceName, MessageTypeRequest, MessageTypeReply, extraOptions, cfg)
}

// Renew performs a DHCPv6 Renew/Reply exchange (RFC 3315 §18.1.3) on
// ifaceName, carrying extraOptions (the server's OPTION_SERVERID plus the
// IA_PD being renewed), and returns the validated Reply.
//
// Renew has no maximum retransmission count (RFC 3315 §5.5); it retries,
// backing off up to RenMaxRT, until ctx is cancelled or a valid Reply
// arrives. Renew is only valid until the binding's T2 elapses, so callers
// should wrap ctx with a deadline at the lease's T2 rather than relying on
// this function to know about lease timing.
func Renew(ctx context.Context, ifaceName string, extraOptions Options) (*Message, error) {
	cfg := exchangeConfig{irt: RenTimeout, mrt: RenMaxRT}
	return doExchange(ctx, ifaceName, MessageTypeRenew, MessageTypeReply, extraOptions, cfg)
}

// Rebind performs a DHCPv6 Rebind/Reply exchange (RFC 3315 §18.1.4) on
// ifaceName, carrying extraOptions (the IA_PD being rebound -- unlike
// Renew, no OPTION_SERVERID, since Rebind is sent when the original server
// hasn't responded and any server may answer), and returns the validated
// Reply.
//
// Like Renew, Rebind has no maximum retransmission count; callers should
// wrap ctx with a deadline at the shortest remaining valid lifetime across
// the binding's addresses/prefixes, since that's the point RFC 3315 says
// the client must stop using them.
func Rebind(ctx context.Context, ifaceName string, extraOptions Options) (*Message, error) {
	cfg := exchangeConfig{irt: RebTimeout, mrt: RebMaxRT}
	return doExchange(ctx, ifaceName, MessageTypeRebind, MessageTypeReply, extraOptions, cfg)
}

// Release performs a DHCPv6 Release/Reply exchange (RFC 3315 §18.1.6) on
// ifaceName, carrying extraOptions (the server's OPTION_SERVERID plus the
// IA_PD being released).
//
// Release retries up to RelMaxRC times; per RFC 3315 §18.1.6, a client
// gives up on the binding locally regardless of whether the server ever
// acknowledged the Release, so errExchangeExhausted is treated as success
// here rather than returned to the caller.
func Release(ctx context.Context, ifaceName string, extraOptions Options) error {
	cfg := exchangeConfig{irt: RelTimeout, mrc: RelMaxRC}
	_, err := doExchange(ctx, ifaceName, MessageTypeRelease, MessageTypeReply, extraOptions, cfg)
	if errors.Is(err, errExchangeExhausted) {
		return nil
	}
	return err
}

// sleepCtx sleeps for d, returning early with ctx.Err() if ctx is cancelled
// first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
