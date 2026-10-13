package radvd

import (
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/shun159/miniteman/pkg/routeradvert"
	"github.com/shun159/molecule/actor"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/net/socket"
	"github.com/shun159/molecule/proc"
)

// advertise, a cast, makes Cfg what the advertiser advertises.
type advertise struct{ Cfg routeradvert.Config }

// Timer keys, and the messages of the timers.
type (
	unsolicited struct{} // the next unsolicited RA is due
	quiet       struct{} // MinDelayBetweenRAs has passed since the last RA
	reply       struct{} // the delayed answer to a Router Solicitation
)

// advertiser sends the Router Advertisements of one interface (RFC 4861
// §6.2): unsolicited, ramping from a fast initial burst to the jittered
// steady-state cadence, and in answer to Router Solicitations, delayed so
// routers don't answer in sync; never two within MinDelayBetweenRAs of each
// other. It is pure: every wait is a timer, the RAs to send are effects
// (sendRA, armRS), and its randomness comes from a generator in its state.
//
// It traps exits, so that on shutdown Terminate sends the final RA with
// RouterLifetime=0 (§6.2.5), telling clients to stop using this router --
// and, its lifetime tracking the router's, this DNS server.
type advertiser struct {
	iface  string
	mac    net.HardwareAddr
	seed   [2]uint64
	sendRA func(ra []byte) actor.Effect // to all nodes on the interface
	armRS  actor.Effect                 // asks the socket for the next Solicitation
}

// state is the advertiser's state.
type state struct {
	rng rand.PCG

	cfg        routeradvert.Config
	configured bool // cfg was given: advertising

	sent     int  // unsolicited RAs sent, for the initial burst
	recent   bool // an RA went out less than MinDelayBetweenRAs ago
	pending  bool // cfg changed while recent: advertise it once quiet
	replying bool // a Solicitation's answer is due
}

func (a advertiser) Init(proc.PID) (state, []actor.Effect, error) {
	return state{rng: *rand.NewPCG(a.seed[0], a.seed[1])}, actor.Do(actor.TrapExit{On: true}), nil
}

func (a advertiser) HandleCall(s state, _ genserver.None, _ genserver.From[genserver.None]) (state, []actor.Effect) {
	return s, nil
}

func (a advertiser) HandleCast(s state, msg advertise) (state, []actor.Effect) {
	switch {
	case !s.configured:
		s.cfg, s.configured = msg.Cfg, true
		return s, actor.Do(sendNow())
	case msg.Cfg == s.cfg:
		return s, nil // nothing a client would see differently
	}
	s.cfg = msg.Cfg
	// Announced at once rather than at the next scheduled RA, up to
	// MaxRtrAdvInterval away -- but never sooner than §6.2.4's floor.
	if s.recent {
		s.pending = true
		return s, nil
	}
	return s, actor.Do(sendNow())
}

func (a advertiser) HandleInfo(s state, msg any) (state, []actor.Effect) {
	switch m := msg.(type) {
	case unsolicited:
		s.sent++
		next := routeradvert.NextUnsolicitedInterval(s.sent, rand.New(&s.rng))
		var effs []actor.Effect
		s, effs = a.send(s)
		return s, append(effs, actor.StartTimer{Key: unsolicited{}, After: next, Msg: unsolicited{}})

	case quiet:
		s.recent = false
		if s.pending {
			s.pending = false
			return s, actor.Do(sendNow())
		}

	case socket.DataMsg:
		effs := actor.Do(a.armRS)
		if !s.configured || s.recent || s.replying || !routeradvert.IsRouterSolicitation(m.Bytes) {
			return s, effs // a recent RA already answers it
		}
		s.replying = true
		after := routeradvert.ReplyDelay(rand.New(&s.rng))
		return s, append(effs, actor.StartTimer{Key: reply{}, After: after, Msg: reply{}})

	case reply:
		s.replying = false
		if !s.recent {
			return a.send(s)
		}

	case socket.SendErrorMsg:
		if isTentative(m.Err) {
			// The link-local source is still DAD-tentative: try again
			// soon, the RA not counted as sent.
			s.sent = max(0, s.sent-1)
			return s, actor.Do(actor.StartTimer{Key: unsolicited{}, After: routeradvert.TentativeRetryInterval, Msg: unsolicited{}})
		}
		return s, actor.Do(actor.Stop{Reason: fmt.Errorf("radvd: sending on %s: %w", a.iface, m.Err)})

	case socket.ErrorMsg:
		return s, actor.Do(actor.Stop{Reason: fmt.Errorf("radvd: reading on %s: %w", a.iface, m.Err)})
	case socket.ClosedMsg:
		return s, actor.Do(actor.Stop{Reason: fmt.Errorf("radvd: socket on %s closed", a.iface)})
	}
	return s, nil
}

// Terminate withdraws the router on the way out, best-effort.
func (a advertiser) Terminate(s state, _ error) []actor.Effect {
	if !s.configured {
		return nil
	}
	return actor.Do(a.sendRA(a.ra(s.cfg, 0)))
}

// send sends an RA of the current Config, and holds off the next for
// MinDelayBetweenRAs.
func (a advertiser) send(s state) (state, []actor.Effect) {
	s.recent = true
	return s, actor.Do(
		a.sendRA(a.ra(s.cfg, routeradvert.AdvDefaultLifetime)),
		actor.StartTimer{Key: quiet{}, After: routeradvert.MinDelayBetweenRAs, Msg: quiet{}},
	)
}

func (a advertiser) ra(cfg routeradvert.Config, lifetime time.Duration) []byte {
	return routeradvert.BuildRA(cfg, lifetime, a.mac).Marshal()
}

// sendNow has the next unsolicited RA go out at once.
func sendNow() actor.Effect {
	return actor.StartTimer{Key: unsolicited{}, After: 0, Msg: unsolicited{}}
}
