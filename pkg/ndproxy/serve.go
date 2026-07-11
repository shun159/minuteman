package ndproxy

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"
)

// sweepInterval drives both probe retransmission (RFC 4861 §10's
// RetransTimer) and active-entry expiry checks -- tied to probeRetransTimer
// so retransmits fire close to on-time.
const sweepInterval = probeRetransTimer

// Config holds Serve's caller-supplied policy hooks. Both are optional.
type Config struct {
	// OnActive is called once a target is confirmed to exist behind iface
	// (a real Neighbor Advertisement matched a probe) -- the caller's
	// chance to install a host route so the kernel forwards target's
	// traffic out iface instead of whichever LAN interface it would
	// otherwise pick. A returned error is logged, not fatal: without a
	// route, traffic for target just keeps arriving proxied and unrouted,
	// no worse than before activation.
	OnActive func(target netip.Addr, iface string) error

	// OnInactive is called when an active entry ages out past activeTTL
	// without being refreshed -- the counterpart to OnActive, so the
	// caller can remove the host route it installed. A later WAN
	// solicitation for the same target starts a fresh LAN probe and, if
	// answered, calls OnActive again.
	OnInactive func(target netip.Addr, iface string)
}

// lanMsg tags a LAN-side NDP message with the interface it arrived on: conn
// itself doesn't know its own interface name.
type lanMsg struct {
	iface string
	msg   message
}

// Serve runs the ND proxy described in this package's doc comment: it
// answers Neighbor Solicitations arriving on wanIface for targets it has
// actively verified exist behind one of lanIfaces, probing there first
// rather than trusting passively-snooped state. Blocks until ctx is
// cancelled, at which point every opened socket is closed and Serve
// returns nil. A non-nil return means opening a socket failed outright, or
// one closed unexpectedly while ctx was still live.
func Serve(ctx context.Context, wanIface string, lanIfaces []string, cfg Config) error {
	wanRX, err := listenPacket(wanIface)
	if err != nil {
		return err
	}
	defer wanRX.Close()

	wanTX, err := listen(wanIface, icmpTypeNeighborAdvert, false)
	if err != nil {
		return err
	}
	defer wanTX.Close()

	lanConns := make(map[string]*conn, len(lanIfaces))
	defer func() {
		for _, c := range lanConns {
			c.Close()
		}
	}()
	for _, iface := range lanIfaces {
		c, err := listen(iface, icmpTypeNeighborAdvert, false)
		if err != nil {
			return err
		}
		lanConns[iface] = c
	}

	wanCh := make(chan message, 16)
	go wanRX.readSolicitations(wanCh)

	lanCh := make(chan lanMsg, 16)
	for iface, c := range lanConns {
		go forwardLANTargets(iface, c, lanCh)
	}

	state := newProxyState()
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case m, ok := <-wanCh:
			if !ok {
				return fmt.Errorf("ndproxy: WAN socket on %s closed unexpectedly", wanIface)
			}
			reply, probe := state.onWANSolicit(time.Now(), m.target, m.source)
			if reply != nil {
				sendReply(wanTX, reply)
			}
			if probe {
				probeLAN(lanConns, m.target)
			}

		case lm, ok := <-lanCh:
			if !ok {
				return fmt.Errorf("ndproxy: LAN sockets on %s closed unexpectedly", wanIface)
			}
			reply, ok := state.onLANAdvert(time.Now(), lm.iface, lm.msg.target)
			if !ok {
				continue
			}
			sendReply(wanTX, reply)
			if cfg.OnActive != nil {
				if err := cfg.OnActive(reply.Target, reply.Iface); err != nil {
					log.Printf("ndproxy: OnActive(%s, %s): %v", reply.Target, reply.Iface, err)
				}
			}

		case now := <-ticker.C:
			retransmit, _, expired := state.sweep(now)
			for _, target := range retransmit {
				probeLAN(lanConns, target)
			}
			if cfg.OnInactive != nil {
				for _, e := range expired {
					cfg.OnInactive(e.Target, e.Iface)
				}
			}
		}
	}
}

// forwardLANTargets relays Neighbor Advertisements read from c into lanCh,
// tagged with iface, until c is closed. Like conn.readTargets itself, sends
// never block: a full lanCh drops the message rather than stalling this
// goroutine forever behind a Serve that has already returned.
func forwardLANTargets(iface string, c *conn, lanCh chan<- lanMsg) {
	raw := make(chan message, 16)
	go c.readTargets(icmpTypeNeighborAdvert, raw)
	for m := range raw {
		select {
		case lanCh <- lanMsg{iface: iface, msg: m}:
		default:
		}
	}
}

// sendReply sends reply out wanTX, logging (not failing Serve) on error --
// the next retransmitted WAN solicitation gets another chance.
func sendReply(wanTX *conn, reply *pendingReply) {
	if err := wanTX.sendAdvertisement(reply.Target, reply.Solicitor); err != nil {
		log.Printf("ndproxy: sending Neighbor Advertisement for %s on WAN: %v", reply.Target, err)
	}
}

// probeLAN sends a Neighbor Solicitation for target out every LAN
// interface, logging (not failing Serve) on a per-interface send error.
func probeLAN(lanConns map[string]*conn, target netip.Addr) {
	for iface, c := range lanConns {
		if err := c.sendSolicitation(target); err != nil {
			log.Printf("ndproxy: sending Neighbor Solicitation for %s on %s: %v", target, iface, err)
		}
	}
}
