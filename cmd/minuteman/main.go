// Command minuteman attaches the DS-Lite (RFC 6333) XDP datapath to a WAN
// and one or more LAN interfaces. The B4 IPv6 address is supplied on the
// command line; the AFTR's address is either supplied via -aftr or, if
// omitted, discovered live via DHCPv6 (RFC 3736 Information-Request +
// RFC 6334 OPTION_AFTR_NAME) and DNS. If -dhcpv6-pd is given, minuteman
// also requests a delegated IPv6 prefix via DHCPv6-PD (RFC 3633) on the WAN
// interface and assigns one /64 (carved from it) to each -lan interface.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/shun159/miniteman/internal/cliconfig"
	"github.com/shun159/miniteman/internal/lanprefix"
	"github.com/shun159/miniteman/pkg/aftrdiscovery"
	"github.com/shun159/miniteman/pkg/datapath"
	"github.com/shun159/miniteman/pkg/prefixdelegation"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var (
		wanIface   = flag.String("wan", "", "WAN interface name (required)")
		b4Addr     = flag.String("b4", "", "B4 IPv6 address, our side of the DS-Lite softwire (required)")
		aftrAddr   = flag.String("aftr", "", "AFTR IPv6 address; if omitted, discovered via DHCPv6 (RFC 3736 + RFC 6334)")
		wanDstMAC  = flag.String("wan-dst-mac", "", "fallback next-hop MAC on the WAN side, used only if FIB lookup can't resolve one")
		statsEvery = flag.Duration("stats-interval", 10*time.Second, "how often to log datapath stats (0 disables)")
		requestPD  = flag.Bool("dhcpv6-pd", false, "request a delegated IPv6 prefix via DHCPv6-PD (RFC 3633) on the WAN interface and assign one /64 per -lan interface from it")
		lans       cliconfig.LANSpecList
	)
	flag.Var(&lans, "lan", "LAN interface as iface=gatewayIP[,mtu] (repeatable, required at least once)")
	flag.Parse()

	if *wanIface == "" || *b4Addr == "" || len(lans) == 0 {
		flag.Usage()
		return errors.New("missing required flags: -wan, -b4, and at least one -lan")
	}

	b4, err := netip.ParseAddr(*b4Addr)
	if err != nil {
		return fmt.Errorf("parsing -b4: %w", err)
	}
	dstMAC, err := cliconfig.ParseMAC(*wanDstMAC)
	if err != nil {
		return fmt.Errorf("parsing -wan-dst-mac: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	aftr, err := resolveAFTR(ctx, *aftrAddr, *wanIface)
	if err != nil {
		return err
	}

	dp, err := datapath.Load()
	if err != nil {
		return fmt.Errorf("loading datapath: %w", err)
	}
	defer dp.Close()

	wanIfindex, err := dp.AttachWAN(*wanIface)
	if err != nil {
		return fmt.Errorf("attaching WAN interface: %w", err)
	}
	log.Printf("attached DS-Lite decap to %s (ifindex %d)", *wanIface, wanIfindex)

	wanNetIface, err := net.InterfaceByName(*wanIface)
	if err != nil {
		return fmt.Errorf("looking up WAN interface: %w", err)
	}

	if err := dp.SetB4Config(datapath.B4Config{
		B4Addr:     b4,
		AFTRAddr:   aftr,
		SrcMAC:     wanNetIface.HardwareAddr,
		DstMAC:     dstMAC,
		WANIfindex: wanIfindex,
	}); err != nil {
		return fmt.Errorf("setting B4 config: %w", err)
	}

	for _, spec := range lans {
		if err := attachLAN(dp, spec); err != nil {
			return err
		}
	}

	var pdWG sync.WaitGroup
	if *requestPD {
		if err := runPrefixDelegation(ctx, *wanIface, lans, &pdWG); err != nil {
			return err
		}
	}
	defer pdWG.Wait()

	logStatsUntilDone(ctx, dp, *statsEvery)
	return nil
}

// runPrefixDelegation acquires a delegated IPv6 prefix via DHCPv6-PD on
// wanIface, assigns the LAN addresses it carves from it and starts
// advertising each carved /64 to LAN clients via Router Advertisements (see
// reconcileAndLog), and starts the background lease-maintenance goroutine
// that keeps renewing it, registering that goroutine on wg so callers can
// wait for its shutdown-triggered Release (and every RA worker's
// shutdown-triggered final RouterLifetime=0 advertisement) to finish before
// exiting.
func runPrefixDelegation(ctx context.Context, wanIface string, lans cliconfig.LANSpecList, wg *sync.WaitGroup) error {
	lease, err := prefixdelegation.Acquire(ctx, wanIface)
	if err != nil {
		return fmt.Errorf("acquiring delegated prefix via DHCPv6-PD: %w", err)
	}

	lanIfaces := make([]string, len(lans))
	for i, spec := range lans {
		lanIfaces[i] = spec.Iface
	}

	raMgr := lanprefix.NewRAManager()
	var assigned []lanprefix.Assignment
	reconcileAndLog := func(l *prefixdelegation.Lease) {
		var err error
		p := l.Prefixes[0]
		assigned, err = lanprefix.Reconcile(p.Prefix, p.ValidLifetime, p.PreferredLifetime, lanIfaces, assigned)
		if err != nil {
			log.Printf("reconciling LAN addresses: %v", err)
		}
		for _, a := range assigned {
			log.Printf("assigned %s to %s (from delegated prefix %s)", a.Address, a.Iface, l.Prefixes[0].Prefix)
		}
		raMgr.Sync(ctx, assigned, wg)
	}
	reconcileAndLog(lease) // initial assignment, before minuteman is considered "up"

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := prefixdelegation.Maintain(ctx, wanIface, lease, reconcileAndLog); err != nil {
			log.Printf("DHCPv6-PD maintenance loop ended unexpectedly: %v", err)
		}
	}()
	return nil
}

// resolveAFTR returns aftrFlag parsed as an IPv6 address if non-empty,
// otherwise discovers the AFTR live via DHCPv6 on wanIface (RFC 3736
// Information-Request + RFC 6334 OPTION_AFTR_NAME, resolved via DNS). The
// discovery call blocks (retrying per RFC 3315) until it succeeds or ctx is
// cancelled -- there's no working DS-Lite path without an AFTR address, so
// waiting (with visible retry behavior in the DHCPv6 client) is preferable
// to an arbitrary timeout.
func resolveAFTR(ctx context.Context, aftrFlag, wanIface string) (netip.Addr, error) {
	if aftrFlag != "" {
		aftr, err := netip.ParseAddr(aftrFlag)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("parsing -aftr: %w", err)
		}
		return aftr, nil
	}

	log.Printf("no -aftr given, discovering AFTR via DHCPv6 on %s", wanIface)
	result, err := aftrdiscovery.Discover(ctx, wanIface)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("discovering AFTR: %w", err)
	}
	log.Printf("discovered AFTR %s -> %s (DNS servers: %v)", result.AFTRName, result.AFTRAddr, result.DNSServers)
	return result.AFTRAddr, nil
}

// attachLAN attaches the encap program to spec's interface and configures
// it, falling back to the interface's current MTU when spec.MTU is unset.
func attachLAN(dp *datapath.Loader, spec cliconfig.LANSpec) error {
	ifindex, err := dp.AttachLAN(spec.Iface)
	if err != nil {
		return fmt.Errorf("attaching LAN interface %s: %w", spec.Iface, err)
	}

	mtu := spec.MTU
	if mtu == 0 {
		iface, err := net.InterfaceByName(spec.Iface)
		if err != nil {
			return fmt.Errorf("looking up LAN interface %s: %w", spec.Iface, err)
		}
		mtu = iface.MTU
	}

	if err := dp.SetLANConfig(ifindex, datapath.LANConfig{
		GatewayIP: spec.GatewayIP,
		InnerMTU:  uint16(mtu),
	}); err != nil {
		return fmt.Errorf("setting LAN config for %s: %w", spec.Iface, err)
	}

	log.Printf("attached DS-Lite encap to %s (ifindex %d, gateway %s, mtu %d)",
		spec.Iface, ifindex, spec.GatewayIP, mtu)
	return nil
}

// logStatsUntilDone logs datapath stats every interval (if positive) until
// ctx is cancelled.
func logStatsUntilDone(ctx context.Context, dp *datapath.Loader, interval time.Duration) {
	if interval <= 0 {
		<-ctx.Done()
		log.Print("shutting down")
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Print("shutting down")
			return
		case <-ticker.C:
			stats, err := dp.Stats()
			if err != nil {
				log.Printf("reading stats: %v", err)
				continue
			}
			log.Printf("stats: %+v", stats)
		}
	}
}
