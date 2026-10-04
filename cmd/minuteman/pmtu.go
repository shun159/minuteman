package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/shun159/miniteman/internal/slowpath"
	"github.com/shun159/miniteman/pkg/datapath"
)

// tunnelPMTUPollInterval is how often the learned softwire path MTU is checked
// for a change. The datapath needs no such poll -- encap clamps against the
// learned value per packet the moment it lands (see tunnel_pmtu_for) -- so this
// only paces the two things userspace owns: the fragment size and the companion
// ip6tnl's MTU. A couple of seconds of lag on those costs a handful of packets
// the ip6tnl fallback carries instead of the in-XDP fragmenter, which is the
// designed degradation, not a failure.
const tunnelPMTUPollInterval = 2 * time.Second

// watchTunnelPMTU keeps the two userspace-owned consequences of a learned
// softwire path MTU in step with what the datapath has learned from ICMPv6
// Packet Too Big messages about its own tunnel packets (RFC 2473 §8, see
// handle_tunnel_icmpv6): the in-XDP fragmenter's per-fragment payload size, and
// the companion ip6tnl's MTU (which governs the fallback paths' inner-IPv4
// fragmentation).
//
// Deriving the fragment size here rather than in the datapath is deliberate:
// encap_fragment_outer and the xdp_softwire_frag<i> programs read frag_unit at
// different moments for the same packet, so a value that changed in between
// would yield a fragment set that can never reassemble. The encap stage now
// snapshots that configured unit into each clone; companion stages use the
// snapshot even when this worker updates the configuration in flight.
//
// It also handles the widening direction: TunnelPMTU stops reporting an aged-out
// reading, so the fragment size and the tunnel MTU go back to the WAN device's
// own without needing any packet to announce that the narrow path is gone.
func watchTunnelPMTU(ctx context.Context, dp *datapath.Loader, tun *slowpath.Tunnel, wanMTU int, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Tracked separately so a failure on one doesn't strand the other at a
		// stale value: whichever didn't take is retried on the next tick, while
		// the one that did stays a no-op.
		appliedFrag, appliedTunnel := wanMTU, wanMTU // what startup configured
		ticker := time.NewTicker(tunnelPMTUPollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			effective := wanMTU
			if learned, ok := dp.TunnelPMTU(); ok && int(learned) < effective {
				effective = int(learned)
			}
			if effective == appliedFrag && effective == appliedTunnel {
				continue
			}

			changed := false
			if effective != appliedFrag {
				if err := dp.SetSoftwireMTU(effective); err != nil {
					log.Printf("softwire path MTU: applying %d to the fragmenter: %v", effective, err)
				} else {
					appliedFrag = effective
					changed = true
				}
			}
			if effective != appliedTunnel {
				// Best-effort, like every other runtime update to this device:
				// the fast path has already adapted.
				if err := tun.SetSoftwireMTU(effective); err != nil {
					log.Printf("softwire path MTU: %v", err)
				} else {
					appliedTunnel = effective
				}
			}

			// Log the reading, not the attempt: a failure above logged itself,
			// and repeating this line every tick until it succeeds would bury it.
			if !changed {
				continue
			}
			if effective < wanMTU {
				log.Printf("softwire path MTU: %d (learned from an ICMPv6 Packet Too Big; WAN MTU is %d)",
					effective, wanMTU)
			} else {
				log.Printf("softwire path MTU: back to the WAN MTU (%d)", wanMTU)
			}
		}
	}()
}
