package softwirectl

import (
	"context"
	"time"

	"github.com/shun159/molecule"
	"github.com/shun159/molecule/proc"
)

// rediscoveryTimeout bounds one re-discovery attempt. Unlike the initial
// discovery (which blocks until it succeeds -- no AFTR, no service), a
// re-discovery is best-effort: the current AFTR still works, so if an attempt
// can't finish promptly it's abandoned and retried next interval. Bounding it
// also bounds how long it holds the WAN's DHCPv6 client, which runs one
// exchange at a time (internal/dhcpv6client), so a stuck Information-Request
// can't starve DHCPv6-PD renewal.
const rediscoveryTimeout = 2 * time.Minute

// DiscoverFunc runs one AFTR discovery attempt, echoing token on an HB46PP
// request.
type DiscoverFunc func(ctx context.Context, token string) (Discovery, error)

// Requests to the discovery process, and the reply.
type (
	discoverReq struct{ Token string }
	// cancelDiscovery, a cast, abandons the attempt in flight; its caller
	// gets no reply.
	cancelDiscovery struct{}

	discoverRep struct {
		Disc    Discovery
		Err     error
		RetryIn time.Duration // after a failure, the backoff for its class
	}
)

// discoverer runs discovery attempts for the controller, one at a time.
// Discovery blocks for up to rediscoveryTimeout, and the controller must be
// able to abandon it on a WAN-address change, so the attempt runs in a
// goroutine of its own, tied to the process's context, while the process stays
// free to receive a cancel. Written against proc rather than as a behaviour for
// that reason: it owns a blocking call.
type discoverer struct {
	discover   DiscoverFunc
	retryDelay func(error) time.Duration
}

// attemptDone is sent by an attempt's goroutine to its process.
type attemptDone struct {
	seq  uint64
	from molecule.From
	rep  discoverRep
}

func (d discoverer) run(s *proc.Self) error {
	if err := s.Node().Register(string(DiscoveryName), s.PID()); err != nil {
		s.InitAck(err)
		return err
	}
	s.InitAck(nil)

	node, self := s.Node(), s.PID()
	var (
		seq    uint64
		cancel context.CancelFunc = func() {}
	)
	defer func() { cancel() }()
	for {
		msg, err := s.Receive(context.Background())
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case molecule.CallMsg:
			req, ok := m.Req.(discoverReq)
			if !ok {
				continue
			}
			cancel() // a new attempt supersedes one still running
			seq++
			ctx, c := context.WithTimeout(s.Context(), rediscoveryTimeout)
			cancel = c
			go func(seq uint64, from molecule.From) {
				defer c()
				disc, err := d.discover(ctx, req.Token)
				rep := discoverRep{Disc: disc, Err: err}
				if err != nil {
					rep.RetryIn = d.retryDelay(err)
				}
				node.Send(self, attemptDone{seq, from, rep})
			}(seq, m.From)

		case molecule.CastMsg:
			if _, ok := m.Req.(cancelDiscovery); ok {
				cancel()
			}

		case attemptDone:
			if m.seq == seq {
				cancel = func() {}
			}
			molecule.SendReply(s, m.from, m.rep)
		}
	}
}
