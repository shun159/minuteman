// Command minuteman attaches the DS-Lite (RFC 6333) XDP datapath to a WAN
// and one or more LAN interfaces. The B4 IPv6 address is supplied on the
// command line; the AFTR's address is either supplied via -aftr or, if
// omitted, discovered live via DHCPv6 (RFC 3736 Information-Request +
// RFC 6334 OPTION_AFTR_NAME) and DNS, falling back to HB46PP provisioning
// (JAIPA's HTTP-based IPv4-over-IPv6 provisioning protocol, capability
// dslite) when the DHCPv6 Reply carries no AFTR-Name. If -dhcpv6-pd is
// given, minuteman also requests a delegated IPv6 prefix via DHCPv6-PD
// (RFC 3633) on the WAN interface and assigns one /64 (carved from it) to
// each -lan interface. If -dns-proxy is given, minuteman also runs a DNS
// proxy (RFC 6333's B4 SHOULD) on every -lan interface's gateway IP,
// forwarding LAN clients' DNS queries directly over IPv6 instead of
// through the DS-Lite softwire.
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
	"github.com/shun159/miniteman/internal/wanextend"
	"github.com/shun159/miniteman/pkg/aftrdiscovery"
	"github.com/shun159/miniteman/pkg/datapath"
	"github.com/shun159/miniteman/pkg/dnsproxy"
	"github.com/shun159/miniteman/pkg/hb46pp"
	"github.com/shun159/miniteman/pkg/prefixdelegation"
	"github.com/shun159/miniteman/pkg/routeradvert"
)

// Default HB46PP client identity sent as provisioning query parameters,
// overridable via -hb46pp-vendor-id/-hb46pp-product/-hb46pp-version.
// "acde48" is the AC-DE-48 OUI conventionally used in documentation and
// examples (it's also what the HB46PP spec's own examples use) --
// minuteman has no IEEE-assigned OUI of its own. A VNE may use vendorid/
// product/version for more than statistics (e.g. per-product rollout or
// workaround decisions per the spec), which is why these are
// configurable rather than permanently hardcoded to the documentation
// values.
const (
	defaultHB46PPVendorID = "acde48-minuteman"
	defaultHB46PPProduct  = "minuteman"
	defaultHB46PPVersion  = "0_1"
)

// hb46ppIdentity bundles the HB46PP client-identity query parameters
// (spec §3.2) so resolveAFTR/discoverViaHB46PP take one value instead of
// three positional strings.
type hb46ppIdentity struct {
	vendorID string
	product  string
	version  string
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var (
		wanIface       = flag.String("wan", "", "WAN interface name (required)")
		b4Addr         = flag.String("b4", "", "B4 IPv6 address, our side of the DS-Lite softwire (required)")
		aftrAddr       = flag.String("aftr", "", "AFTR IPv6 address; if omitted, discovered via DHCPv6 (RFC 3736 + RFC 6334)")
		wanDstMAC      = flag.String("wan-dst-mac", "", "fallback next-hop MAC on the WAN side, used only if FIB lookup can't resolve one")
		statsEvery     = flag.Duration("stats-interval", 10*time.Second, "how often to log datapath stats (0 disables)")
		requestPD      = flag.Bool("dhcpv6-pd", false, "request a delegated IPv6 prefix via DHCPv6-PD (RFC 3633) on the WAN interface and assign one /64 per -lan interface from it")
		ndProxy        = flag.Bool("ndproxy", false, "extend the WAN interface's own SLAAC /64 onto every -lan interface via RFC 4389 Neighbor Discovery Proxy, for ISPs that hand out a single WAN /64 with no DHCPv6-PD delegation (mutually exclusive with -dhcpv6-pd)")
		dnsProxyOn     = flag.Bool("dns-proxy", false, "run a DNS proxy (RFC 6333's B4 SHOULD) on every -lan interface's gateway IP, port 53/UDP+TCP, forwarding queries directly over IPv6 to -dns-server (or the DHCPv6-learned DNS servers, if -dns-server is omitted) instead of through the DS-Lite softwire")
		hb46ppVendorID = flag.String("hb46pp-vendor-id", defaultHB46PPVendorID, "HB46PP vendorid query parameter sent during provisioning discovery fallback (vendor OUI, optionally -suffix)")
		hb46ppProduct  = flag.String("hb46pp-product", defaultHB46PPProduct, "HB46PP product query parameter sent during provisioning discovery fallback")
		hb46ppVersion  = flag.String("hb46pp-version", defaultHB46PPVersion, "HB46PP version query parameter sent during provisioning discovery fallback (digits/underscores only)")
		lans           cliconfig.LANSpecList
		dnsServersFlag cliconfig.AddrList
	)
	flag.Var(&lans, "lan", "LAN interface as iface=gatewayIP[,mtu] (repeatable, required at least once)")
	flag.Var(&dnsServersFlag, "dns-server", "upstream DNS server for -dns-proxy to forward to (repeatable, IPv6 recommended -- see -dns-proxy); defaults to the DNS servers learned via DHCPv6 during AFTR discovery if omitted")
	flag.Parse()

	if *wanIface == "" || *b4Addr == "" || len(lans) == 0 {
		flag.Usage()
		return errors.New("missing required flags: -wan, -b4, and at least one -lan")
	}
	if *requestPD && *ndProxy {
		flag.Usage()
		return errors.New("-dhcpv6-pd and -ndproxy are mutually exclusive WAN IPv6 provisioning models")
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

	identity := hb46ppIdentity{vendorID: *hb46ppVendorID, product: *hb46ppProduct, version: *hb46ppVersion}
	aftr, discoveredDNSServers, err := resolveAFTR(ctx, *aftrAddr, *wanIface, identity)
	if err != nil {
		return err
	}

	dnsServers := discoveredDNSServers
	if len(dnsServersFlag) > 0 {
		dnsServers = dnsServersFlag
	}
	if *dnsProxyOn && len(dnsServers) == 0 {
		return errors.New("-dns-proxy needs at least one DNS server: none were learned via DHCPv6 (likely because -aftr was given directly, skipping DHCPv6 discovery) and none were given via -dns-server")
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

	// AttachWAN just enabled IPv6 forwarding, and that transition makes the
	// kernel purge every RA-learned default route -- without re-soliciting,
	// the WAN has no route to the AFTR until the ISP's next unsolicited RA,
	// potentially minutes away (see configureWANSysctls in pkg/datapath).
	go func() {
		if err := routeradvert.SolicitRouters(ctx, *wanIface); err != nil && ctx.Err() == nil {
			log.Printf("soliciting router advertisements on %s: %v", *wanIface, err)
		}
	}()

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

	var bgWG sync.WaitGroup
	if *requestPD {
		if err := runPrefixDelegation(ctx, *wanIface, lans, &bgWG); err != nil {
			return err
		}
	}
	if *ndProxy {
		if err := runNDProxy(ctx, *wanIface, wanIfindex, lans, &bgWG); err != nil {
			return err
		}
	}
	if *dnsProxyOn {
		runDNSProxy(ctx, lans, dnsServers, &bgWG)
	}
	defer bgWG.Wait()

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

// runNDProxy delegates the whole -ndproxy CPE policy to
// internal/wanextend.Serve: learning the WAN interface's own SLAAC /64,
// re-advertising it on every -lan interface with the On-Link flag cleared
// (see routeradvert.Config.OnLink's doc) and keeping that advertisement in
// sync if the WAN prefix later changes, and running pkg/ndproxy.Serve on
// wanIface to answer WAN-side Neighbor Solicitations for LAN hosts it
// actively verifies exist. wanextend.Serve registers every goroutine it
// starts on wg, so run() waits for their shutdown-triggered final RAs and
// socket cleanup before returning.
func runNDProxy(ctx context.Context, wanIface string, wanIfindex uint32, lans cliconfig.LANSpecList, wg *sync.WaitGroup) error {
	lanIfaces := make([]string, len(lans))
	for i, spec := range lans {
		lanIfaces[i] = spec.Iface
	}
	return wanextend.Serve(ctx, wanIface, int(wanIfindex), lanIfaces, wg)
}

// runDNSProxy starts pkg/dnsproxy.Serve listening on every -lan interface's
// gateway IP, forwarding to dnsServers, tracked on wg so run() waits for
// its sockets to close on shutdown. Unlike runPrefixDelegation/runNDProxy,
// this can't fail at startup in a way worth surfacing synchronously (the
// listen addresses are already-validated -lan gateway IPs; a bind failure
// would mean something else is already using port 53 on one of them, which
// Serve itself logs), so it doesn't return an error.
func runDNSProxy(ctx context.Context, lans cliconfig.LANSpecList, dnsServers []netip.Addr, wg *sync.WaitGroup) {
	listenAddrs := make([]netip.Addr, len(lans))
	for i, spec := range lans {
		listenAddrs[i] = spec.GatewayIP
	}

	log.Printf("DNS proxy: listening on %v, forwarding to %v", listenAddrs, dnsServers)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := dnsproxy.Serve(ctx, dnsproxy.Config{ListenAddrs: listenAddrs, Upstreams: dnsServers}); err != nil {
			log.Printf("DNS proxy ended unexpectedly: %v", err)
		}
	}()
}

// resolveAFTR returns aftrFlag parsed as an IPv6 address if non-empty,
// otherwise discovers the AFTR live via DHCPv6 on wanIface (RFC 3736
// Information-Request + RFC 6334 OPTION_AFTR_NAME, resolved via DNS). If
// the DHCPv6 Reply carries no AFTR-Name, it falls back to HB46PP
// provisioning (capability dslite, identified as identity) using the DNS
// servers from that same Reply, retrying the whole DHCPv6-then-HB46PP
// chain on HB46PP failure with the HB46PP spec's backoff for the failure
// class. Discovery blocks until it succeeds or ctx is cancelled -- there's
// no working DS-Lite path without an AFTR address, so waiting (with
// visible retry behavior) is preferable to an arbitrary timeout.
//
// The second return is the DNS servers learned along the way (RFC 3646
// OPTION_DNS_SERVERS from the same DHCPv6 Reply), for -dns-proxy to use as
// its default upstreams -- nil when aftrFlag was given directly, since
// that path skips the DHCPv6 exchange entirely.
func resolveAFTR(ctx context.Context, aftrFlag, wanIface string, identity hb46ppIdentity) (netip.Addr, []netip.Addr, error) {
	if aftrFlag != "" {
		aftr, err := netip.ParseAddr(aftrFlag)
		if err != nil {
			return netip.Addr{}, nil, fmt.Errorf("parsing -aftr: %w", err)
		}
		return aftr, nil, nil
	}

	log.Printf("no -aftr given, discovering AFTR via DHCPv6 on %s", wanIface)
	for {
		result, err := aftrdiscovery.Discover(ctx, wanIface)
		if err == nil {
			log.Printf("discovered AFTR %s -> %s (DNS servers: %v)", result.AFTRName, result.AFTRAddr, result.DNSServers)
			return result.AFTRAddr, result.DNSServers, nil
		}
		if !errors.Is(err, aftrdiscovery.ErrNoAFTRName) {
			return netip.Addr{}, nil, fmt.Errorf("discovering AFTR: %w", err)
		}

		// result is aftrdiscovery's documented partial result here: the
		// Reply had DNS servers but no AFTR-Name.
		log.Printf("DHCPv6 Reply carried no AFTR-Name, trying HB46PP provisioning (DNS servers: %v)", result.DNSServers)
		aftr, err := discoverViaHB46PP(ctx, result.DNSServers, identity)
		if err == nil {
			return aftr, result.DNSServers, nil
		}

		delay := hb46pp.RetryDelay(err)
		log.Printf("HB46PP provisioning failed: %v (retrying discovery in %v)", err, delay.Round(time.Second))
		select {
		case <-ctx.Done():
			return netip.Addr{}, nil, ctx.Err()
		case <-time.After(delay):
		}
	}
}

// discoverViaHB46PP runs one HB46PP provisioning exchange advertising the
// dslite capability and returns the AFTR address it yields. dnsServers
// (from the DHCPv6 Reply) are the VNE's own resolvers, which is what the
// 4over6.info TXT lookup must go through.
func discoverViaHB46PP(ctx context.Context, dnsServers []netip.Addr, identity hb46ppIdentity) (netip.Addr, error) {
	result, err := hb46pp.Discover(ctx, hb46pp.Config{
		Client: hb46pp.ClientInfo{
			VendorID:     identity.vendorID,
			Product:      identity.product,
			Version:      identity.version,
			Capabilities: []string{"dslite"},
		},
		DNSServers: dnsServers,
	})
	if err != nil {
		return netip.Addr{}, err
	}
	if !result.AFTRAddr.IsValid() {
		return netip.Addr{}, fmt.Errorf("provisioning server returned no DS-Lite parameters (offered order: %v)", result.Provisioning.Order)
	}
	log.Printf("HB46PP: provisioned by %q (%s): AFTR %s -> %s (refresh in %v)",
		result.Provisioning.EnablerName, result.Provisioning.ServiceName,
		result.AFTRName, result.AFTRAddr, result.RefreshInterval)
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
