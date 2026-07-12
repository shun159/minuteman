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
// through the DS-Lite softwire. If -dhcpv4 is given, minuteman also runs a
// DHCPv4 server (RFC 2131) on every -lan interface, handing LAN clients an
// address from that interface's subnet plus the CPE as their router and DNS.
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
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/shun159/miniteman/internal/cliconfig"
	"github.com/shun159/miniteman/internal/lanprefix"
	"github.com/shun159/miniteman/internal/wanextend"
	"github.com/shun159/miniteman/pkg/aftrdiscovery"
	"github.com/shun159/miniteman/pkg/datapath"
	"github.com/shun159/miniteman/pkg/dhcpv4"
	"github.com/shun159/miniteman/pkg/dnsproxy"
	"github.com/shun159/miniteman/pkg/hb46pp"
	"github.com/shun159/miniteman/pkg/prefixdelegation"
	"github.com/shun159/miniteman/pkg/routeradvert"

	"golang.org/x/sys/unix"
)

// tunnelOverhead is the DS-Lite IPv4-in-IPv6 encapsulation overhead (the
// 40-byte outer IPv6 header, matching the datapath's TUNNEL_L3_OVERHEAD).
// It's subtracted from the WAN MTU to derive the interface MTU the DHCPv4
// server advertises to LAN clients, so they size packets to fit the
// softwire without relying on in-path PMTUD.
const tunnelOverhead = 40

// minDHCPv4Lease is the shortest lease -dhcpv4-lease may set. Below roughly
// this, the RFC 2131 §4.4.5 renewal timers (T1 = lease/2, T2 = 7/8 lease)
// stop being distinct whole seconds, and such short leases would hammer the
// server with renewals regardless; it's a misconfiguration floor, not a
// protocol constant.
const minDHCPv4Lease = time.Minute

// dhcpMinMTU is RFC 791's minimum IPv4 MTU (68 bytes) and RFC 2132 §5.1's
// floor for the Interface MTU option; a computed/configured MTU below it is
// dropped rather than advertised.
const dhcpMinMTU = 68

// dnsProxyBindRetries/dnsProxyBindRetryInterval bound how long startDNSProxy
// waits out an EADDRNOTAVAIL when binding a LAN link-local address: the
// kernel returns that while the address is still DAD-tentative, which right
// after XDP attach bounces the LAN link (see routeradvert's
// tentativeRetryInterval) it briefly is. ~10 * 1s covers several DAD cycles;
// any *other* bind error (e.g. EADDRINUSE, port 53 already taken) fails
// immediately rather than being retried, so a real misconfiguration surfaces
// at once.
const (
	dnsProxyBindRetries       = 10
	dnsProxyBindRetryInterval = time.Second
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

// onlineCPUs returns the CPU ids to fan native-IPv6 forwarding across when
// -ipv6-sw-rss is set: every logical CPU available to this process (0..N-1).
// runtime.NumCPU already respects CPU-affinity/cgroup limits, so this matches
// the CPUs the datapath can actually be scheduled on.
func onlineCPUs() []uint32 {
	n := runtime.NumCPU()
	cpus := make([]uint32, n)
	for i := range cpus {
		cpus[i] = uint32(i)
	}
	return cpus
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
		dhcpv4On       = flag.Bool("dhcpv4", false, "run a DHCPv4 server (RFC 2131) on every -lan interface, handing LAN clients an address from that interface's subnet (see -lan's optional /prefixlen, default /24), with the gateway IP as router and DNS (pair with -dns-proxy) and a DS-Lite-adjusted MTU")
		dhcpv4Lease    = flag.Duration("dhcpv4-lease", 12*time.Hour, "DHCPv4 lease duration handed to LAN clients (with -dhcpv4)")
		ipv6SwRSS      = flag.Bool("ipv6-sw-rss", false, "spread native-IPv6 forwarding-fastpath work across CPUs with a cpumap software-RSS stage; leave off when the NIC's hardware RSS already distributes flows (e.g. mlx4)")
		hb46ppVendorID = flag.String("hb46pp-vendor-id", defaultHB46PPVendorID, "HB46PP vendorid query parameter sent during provisioning discovery fallback (vendor OUI, optionally -suffix)")
		hb46ppProduct  = flag.String("hb46pp-product", defaultHB46PPProduct, "HB46PP product query parameter sent during provisioning discovery fallback")
		hb46ppVersion  = flag.String("hb46pp-version", defaultHB46PPVersion, "HB46PP version query parameter sent during provisioning discovery fallback (digits/underscores only)")
		lans           cliconfig.LANSpecList
		dnsServersFlag cliconfig.AddrList
		dhcpv4DNSFlag  cliconfig.AddrList
	)
	flag.Var(&lans, "lan", "LAN interface as iface=gatewayIP[/prefixlen][,mtu] (repeatable, required at least once)")
	flag.Var(&dnsServersFlag, "dns-server", "upstream DNS server for -dns-proxy to forward to (repeatable, IPv6 recommended -- see -dns-proxy); defaults to the DNS servers learned via DHCPv6 during AFTR discovery if omitted")
	flag.Var(&dhcpv4DNSFlag, "dhcpv4-dns", "IPv4 DNS server to advertise to DHCPv4 clients (repeatable, with -dhcpv4); if unset, the -lan gateway IP is advertised when -dns-proxy is running to answer there, otherwise no DNS is advertised")
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
	for _, a := range dhcpv4DNSFlag {
		if !a.Is4() {
			return fmt.Errorf("-dhcpv4-dns %s must be an IPv4 address (DHCPv4 option 6 carries only IPv4 DNS servers)", a)
		}
	}
	if *dhcpv4On && *dhcpv4Lease < minDHCPv4Lease {
		return fmt.Errorf("-dhcpv4-lease must be at least %v (shorter leases don't yield valid T1/T2 renewal timers)", minDHCPv4Lease)
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

	if *ipv6SwRSS {
		cpus := onlineCPUs()
		if err := dp.EnableIPv6SoftwareRSS(cpus); err != nil {
			return fmt.Errorf("enabling IPv6 software RSS: %w", err)
		}
		log.Printf("IPv6 software RSS: fanning native-IPv6 forwarding across %d CPUs", len(cpus))
	}

	var bgWG sync.WaitGroup
	// Started before runPrefixDelegation/runNDProxy so the exact link-local
	// addresses it bound can be handed to them as RDNSS entries: an RA must
	// never promise a DNS server this proxy hasn't actually bound (see
	// startDNSProxy's own doc). rdnssByIface is empty when -dns-proxy is off,
	// so no RDNSS is advertised then.
	var rdnssByIface map[string]netip.Addr
	if *dnsProxyOn {
		var err error
		rdnssByIface, err = startDNSProxy(ctx, lans, dnsServers, &bgWG)
		if err != nil {
			return fmt.Errorf("-dns-proxy: %w", err)
		}
	}
	if *requestPD {
		if err := runPrefixDelegation(ctx, *wanIface, lans, rdnssByIface, &bgWG); err != nil {
			return err
		}
	}
	if *ndProxy {
		if err := runNDProxy(ctx, *wanIface, wanIfindex, lans, rdnssByIface, &bgWG); err != nil {
			return err
		}
	}
	if *dhcpv4On {
		if err := runDHCPv4(ctx, lans, dhcpv4DNSFlag, *dnsProxyOn, wanNetIface.MTU, *dhcpv4Lease, &bgWG); err != nil {
			return err
		}
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
// exiting. rdnssByIface is forwarded to lanprefix.NewRAManager (see its own
// doc) -- it's the map of link-local addresses startDNSProxy actually bound,
// so RDNSS is advertised only where a DNS proxy is really listening.
func runPrefixDelegation(ctx context.Context, wanIface string, lans cliconfig.LANSpecList, rdnssByIface map[string]netip.Addr, wg *sync.WaitGroup) error {
	lease, err := prefixdelegation.Acquire(ctx, wanIface)
	if err != nil {
		return fmt.Errorf("acquiring delegated prefix via DHCPv6-PD: %w", err)
	}

	lanIfaces := make([]string, len(lans))
	for i, spec := range lans {
		lanIfaces[i] = spec.Iface
	}

	raMgr := lanprefix.NewRAManager(rdnssByIface)
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
// socket cleanup before returning. rdnssByIface is forwarded to
// wanextend.Serve (see its own doc) -- it's the map of link-local addresses
// startDNSProxy actually bound, so RDNSS is advertised only where a DNS
// proxy is really listening.
func runNDProxy(ctx context.Context, wanIface string, wanIfindex uint32, lans cliconfig.LANSpecList, rdnssByIface map[string]netip.Addr, wg *sync.WaitGroup) error {
	lanIfaces := make([]string, len(lans))
	for i, spec := range lans {
		lanIfaces[i] = spec.Iface
	}
	return wanextend.Serve(ctx, wanIface, int(wanIfindex), lanIfaces, rdnssByIface, wg)
}

// startDNSProxy opens pkg/dnsproxy's listening sockets (via dnsproxy.Listen,
// synchronously) on every -lan interface's IPv4 gateway IP and its own
// link-local IPv6 address, starts serving on wg, and returns a map of -lan
// interface -> the link-local address it actually bound there. Called, and
// its success checked, *before* runPrefixDelegation/runNDProxy: those
// advertise exactly the addresses in that returned map as RDNSS entries (RFC
// 8106), so an RA can never promise a DNS server dnsproxy.Listen didn't
// actually bind -- both a bind failure and a link-local that never became
// available are reflected here (fail-fast / omitted from the map) rather
// than diverging from what the RA workers independently believe, mirroring
// pkg/dhcpv4.New's own synchronous-failure rationale.
//
// A LAN link-local that's still DAD-tentative at bind time yields
// EADDRNOTAVAIL, which is retried on the tentative cadence (see
// dnsProxyBindRetries); any other bind error (port 53 in use, etc.) fails
// immediately. A -lan interface with no link-local address at all is logged
// and left out of the map (no RDNSS for it), while its IPv4 listener still
// starts.
func startDNSProxy(ctx context.Context, lans cliconfig.LANSpecList, dnsServers []netip.Addr, wg *sync.WaitGroup) (map[string]netip.Addr, error) {
	listenAddrs := make([]netip.Addr, 0, len(lans)*2)
	rdnssByIface := make(map[string]netip.Addr, len(lans))
	for _, spec := range lans {
		listenAddrs = append(listenAddrs, spec.GatewayIP)
		if ll, err := routeradvert.LinkLocalAddr(spec.Iface); err != nil {
			log.Printf("DNS proxy: not listening on %s's link-local address (no RDNSS for it): %v", spec.Iface, err)
		} else {
			listenAddrs = append(listenAddrs, ll)
			rdnssByIface[spec.Iface] = ll
		}
	}

	srv, err := listenDNSProxyTolerantOfTentative(ctx, dnsproxy.Config{ListenAddrs: listenAddrs, Upstreams: dnsServers})
	if err != nil {
		return nil, err
	}

	log.Printf("DNS proxy: listening on %v, forwarding to %v", listenAddrs, dnsServers)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Serve(ctx); err != nil {
			log.Printf("DNS proxy ended unexpectedly: %v", err)
		}
	}()
	return rdnssByIface, nil
}

// listenDNSProxyTolerantOfTentative calls dnsproxy.Listen, retrying only
// while it fails with EADDRNOTAVAIL (a LAN link-local still DAD-tentative --
// see dnsProxyBindRetries). Any other error, or exhausting the retries, is
// returned; ctx cancellation aborts the wait.
func listenDNSProxyTolerantOfTentative(ctx context.Context, cfg dnsproxy.Config) (*dnsproxy.Server, error) {
	for attempt := 0; ; attempt++ {
		srv, err := dnsproxy.Listen(cfg)
		if err == nil {
			return srv, nil
		}
		if !errors.Is(err, unix.EADDRNOTAVAIL) || attempt >= dnsProxyBindRetries {
			return nil, err
		}
		log.Printf("DNS proxy: a listen address is still tentative, retrying: %v", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(dnsProxyBindRetryInterval):
		}
	}
}

// runDHCPv4 builds a pkg/dhcpv4.InterfaceConfig for every -lan interface,
// constructs the server synchronously (so an invalid subnet or a socket
// failure fails run() rather than surfacing only in a log line), and starts
// it on wg. Each interface serves its own subnet (from -lan's /prefixlen),
// offers its gateway IP as router, and advertises an interface MTU sized for
// the DS-Lite softwire: the -lan MTU if set, else the WAN MTU minus the
// 40-byte tunnel overhead (dropped if that falls below the IPv4 minimum). A
// -lan without an IPv4 subnet (an IPv6-only gateway) is rejected.
//
// The DNS server offered (option 6) is dnsOverride (-dhcpv4-dns) if given,
// else this CPE's gateway when -dns-proxy is running to answer at it; with
// neither, no DNS is advertised at all rather than pointing clients at a port
// nothing listens on.
func runDHCPv4(ctx context.Context, lans cliconfig.LANSpecList, dnsOverride []netip.Addr, dnsProxyOn bool, wanMTU int, lease time.Duration, wg *sync.WaitGroup) error {
	var cfgs []dhcpv4.InterfaceConfig
	for _, spec := range lans {
		if !spec.Subnet.IsValid() || !spec.Subnet.Addr().Is4() {
			return fmt.Errorf("-dhcpv4: LAN interface %s has no IPv4 subnet (its -lan gateway %s is not IPv4)", spec.Iface, spec.GatewayIP)
		}

		dns := dnsOverride
		switch {
		case len(dns) > 0:
			// use the operator's explicit -dhcpv4-dns
		case dnsProxyOn:
			dns = []netip.Addr{spec.GatewayIP} // point clients at this CPE's -dns-proxy
		default:
			log.Printf("DHCPv4: advertising no DNS server on %s (enable -dns-proxy or set -dhcpv4-dns)", spec.Iface)
		}

		mtu := spec.MTU
		if mtu == 0 && wanMTU > tunnelOverhead {
			mtu = wanMTU - tunnelOverhead
		}
		if mtu != 0 && (mtu < dhcpMinMTU || mtu > 0xffff) {
			log.Printf("DHCPv4: computed MTU %d out of range on %s, not advertising option 26", mtu, spec.Iface)
			mtu = 0
		}

		cfgs = append(cfgs, dhcpv4.InterfaceConfig{
			Iface:      spec.Iface,
			ServerIP:   spec.GatewayIP,
			Subnet:     spec.Subnet,
			DNSServers: dns,
			MTU:        uint16(mtu),
			LeaseTime:  lease,
		})
		log.Printf("DHCPv4: serving %s on %s (router %s, DNS %v, lease %v, MTU %d)",
			spec.Subnet, spec.Iface, spec.GatewayIP, dns, lease, mtu)
	}

	srv, err := dhcpv4.New(cfgs)
	if err != nil {
		return fmt.Errorf("starting DHCPv4 server: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Serve(ctx); err != nil {
			log.Printf("DHCPv4 server ended unexpectedly: %v", err)
		}
	}()
	return nil
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
