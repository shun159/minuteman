package main

import (
	"context"
	"log"
	"net/netip"

	"github.com/shun159/miniteman/internal/slowpath"
	"github.com/shun159/miniteman/internal/softwirectl"
	"github.com/shun159/miniteman/pkg/datapath"
	"github.com/shun159/miniteman/pkg/dhcpv6"
	"github.com/shun159/miniteman/pkg/hb46pp"
	"github.com/shun159/miniteman/pkg/netlink"
	"github.com/shun159/molecule/application"
)

// startSoftwireControl starts the supervision tree owning the live softwire
// endpoints (internal/softwirectl): AFTR re-discovery with the flow-preserving
// migration when the AFTR is dynamic, and the hard switch on a WAN-address
// change when the B4 is.
//
// The tree is an application of apps, stopped before run's deferred tun.Close
// and dp.Close; closeNL closes the netlink socket it uses, for run to defer
// so that it runs after.
//
// fallbackDNS is the DHCPv6-PD lease's servers as of startup, and is not
// refreshed from later renewals; likewise, a re-discovery's DNS servers are
// not handed to a running -dns-proxy (docs/rfc-compliance-backlog.md).
func startSoftwireControl(ctx context.Context, apps *application.Running, dhcp dhcpv6.Exchanger, dp *datapath.Loader, tun *slowpath.Tunnel, b4 netip.Addr, dynamicB4, aftrDynamic bool, wanIface string, wanIfindex uint32, identity hb46ppIdentity, initial aftrDiscovery, fallbackDNS []netip.Addr) (closeNL func(), err error) {
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
	closeNL = func() {
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
			Discover: func(ctx context.Context, token string) (softwirectl.Discovery, error) {
				disc, err := discoverAFTROnce(ctx, dhcp, wanIface, identity, token, fallbackDNS)
				return disc.toSoftwirectl(), err
			},
			RetryDelay: hb46pp.RetryDelay,
		},
	})

	if err := apps.Start(ctx, app("softwire control", spec)); err != nil {
		closeNL()
		return nil, err
	}
	return closeNL, nil
}

func (d aftrDiscovery) toSoftwirectl() softwirectl.Discovery {
	return softwirectl.Discovery{
		AFTR:        d.aftr,
		DNSServers:  d.dnsServers,
		Refresh:     d.refresh,
		HB46PPToken: d.hb46ppToken,
	}
}
