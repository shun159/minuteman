package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/shun159/miniteman/internal/slowpath"
	"github.com/shun159/miniteman/internal/softwirectl"
	"github.com/shun159/miniteman/pkg/datapath"
	"github.com/shun159/miniteman/pkg/hb46pp"
	"github.com/shun159/miniteman/pkg/netlink"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/proc"
)

// softwireStopTimeout bounds how long shutdown waits for the softwire control
// tree to stop, before tun and dp are closed under it anyway.
const softwireStopTimeout = 10 * time.Second

// startSoftwireControl starts the supervision tree owning the live softwire
// endpoints (internal/softwirectl): AFTR re-discovery with the flow-preserving
// migration when the AFTR is dynamic, and the hard switch on a WAN-address
// change when the B4 is.
//
// Registered on wg: on shutdown the tree is stopped before run's deferred
// tun.Close and dp.Close. If the tree gives up on its own -- a child
// restarting past the supervisor's intensity -- it fails the whole of
// minuteman through fail, so that whatever restarts minuteman starts it
// cleanly.
//
// fallbackDNS is the DHCPv6-PD lease's servers as of startup, and is not
// refreshed from later renewals; likewise, a re-discovery's DNS servers are
// not handed to a running -dns-proxy (docs/rfc-compliance-backlog.md).
func startSoftwireControl(ctx context.Context, fail context.CancelCauseFunc, dp *datapath.Loader, tun *slowpath.Tunnel, b4 netip.Addr, dynamicB4, aftrDynamic bool, wanIface string, wanIfindex uint32, identity hb46ppIdentity, initial aftrDiscovery, fallbackDNS []netip.Addr, wg *sync.WaitGroup) error {
	var nl *netlink.Socket
	var router softwirectl.Router
	if dynamicB4 {
		var err error
		nl, err = netlink.Open()
		if err != nil {
			log.Printf("dynamic B4: cannot open netlink socket to watch the WAN source: %v (WAN-change re-selection disabled)", err)
			dynamicB4 = false
		} else {
			router = nl
		}
	}
	closeNL := func() {
		if nl != nil {
			nl.Close()
		}
	}

	sw := softwirectl.NewSoftwire(dp, tun, router, int(wanIfindex), softwirectl.Endpoints{B4: b4, AFTR: initial.aftr})
	spec := softwirectl.Spec(softwirectl.Config{
		Softwire: sw,
		Controller: softwirectl.Controller{
			DynamicAFTR: aftrDynamic,
			DynamicB4:   dynamicB4,
			Initial:     initial.toSoftwirectl(),
		},
		Discover: func(ctx context.Context, token string) (softwirectl.Discovery, error) {
			disc, err := discoverAFTROnce(ctx, wanIface, identity, token, fallbackDNS)
			return disc.toSoftwirectl(), err
		},
		RetryDelay: hb46pp.RetryDelay,
	})

	node := proc.NewNode("")
	sup, err := supervisor.Start(ctx, node, spec)
	if err != nil {
		closeNL()
		return fmt.Errorf("starting softwire control: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeNL()
		down, cancel := node.Watch(context.Background(), sup)
		defer cancel()
		select {
		case <-ctx.Done():
			stopCtx, cancel := context.WithTimeout(context.Background(), softwireStopTimeout)
			defer cancel()
			if err := supervisor.Stop(stopCtx, node, sup); err != nil {
				log.Printf("stopping softwire control: %v", err)
			}
		case <-down.Done():
			fail(fmt.Errorf("softwire control gave up: %w", context.Cause(down)))
		}
	}()
	return nil
}

func (d aftrDiscovery) toSoftwirectl() softwirectl.Discovery {
	return softwirectl.Discovery{
		AFTR:        d.aftr,
		DNSServers:  d.dnsServers,
		Refresh:     d.refresh,
		HB46PPToken: d.hb46ppToken,
	}
}
