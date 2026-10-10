// Command minuteman attaches the DS-Lite (RFC 6333) XDP datapath to a WAN
// and one or more LAN interfaces. The B4 IPv6 address is either supplied via
// -b4 or, if omitted, tracked dynamically from the WAN interface's
// kernel-chosen source toward the AFTR (RFC 6724) and re-selected when the WAN
// address changes (the DS-Lite B4-address change of RFC 7785); the AFTR's
// address is either supplied via -aftr
// or, if omitted, discovered live via DHCPv6 (RFC 3736 Information-Request +
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
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shun159/miniteman/internal/cliconfig"
	"github.com/shun159/miniteman/internal/dhcpv4server"
	"github.com/shun159/miniteman/internal/dhcpv6client"
	"github.com/shun159/miniteman/internal/dnsproxy"
	"github.com/shun159/miniteman/internal/fragpath"
	"github.com/shun159/miniteman/internal/lanprefix"
	"github.com/shun159/miniteman/internal/ndppd"
	"github.com/shun159/miniteman/internal/radvd"
	"github.com/shun159/miniteman/internal/slowpath"
	"github.com/shun159/miniteman/internal/softwirectl"
	"github.com/shun159/miniteman/internal/wanextend"
	"github.com/shun159/miniteman/pkg/aftrdiscovery"
	"github.com/shun159/miniteman/pkg/datapath"
	"github.com/shun159/miniteman/pkg/dhcpv4"
	"github.com/shun159/miniteman/pkg/dhcpv6"
	"github.com/shun159/miniteman/pkg/hb46pp"
	"github.com/shun159/miniteman/pkg/netlink"
	"github.com/shun159/miniteman/pkg/prefixdelegation"
	"github.com/shun159/miniteman/pkg/routeradvert"
	"github.com/shun159/molecule/application"
	"github.com/shun159/molecule/proc"
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

// informationRequestTimeout bounds how long AFTR discovery waits for a reply
// to its DHCPv6 Information-Request before falling forward to HB46PP.
// RFC 3315 §18.1.5 sets no maximum retransmission count or duration for this
// exchange, so pkg/dhcpv6 retries it indefinitely -- correct against a
// network that answers eventually, an indefinite startup hang against one
// that never will. Two access tiers of the NTT East FLET'S IPoE spec state
// outright that the network does not answer it (光クロス §4.4.2.1.2, 光25G
// §2.4.1.1.2), and those are exactly the deployments HB46PP exists to serve,
// so a bound is what lets the fallback ever run.
//
// 30s covers roughly five retransmissions at RFC 3315's 1s/doubling schedule
// -- generous against a slow or briefly-unready server, while keeping startup
// on a network that will never answer down to half a minute. Timing out is
// not a permanent verdict: resolveAFTR's loop re-runs the whole chain,
// Information-Request included, on every retry.
const informationRequestTimeout = 30 * time.Second

// noReplyRetryCap bounds the backoff after an attempt in which the DHCPv6
// Information-Request went unanswered *and* the HB46PP fallback then failed.
// The delay would otherwise come from hb46pp.RetryDelay's verdict on the
// HB46PP error alone -- up to 1-3 hours for ErrNotProvisioned -- but having
// heard nothing from DHCPv6 we have no evidence the network is
// HB46PP-unprovisioned rather than merely slow to come up, and a wrong guess
// there costs hours of no IPv4. Attempts that did draw a DHCPv6 Reply keep
// the spec's full backoff, since there the HB46PP verdict rests on something.
const noReplyRetryCap = 5 * time.Minute

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
	// Subcommand dispatch, before flag.Parse so the flag-only invocation --
	// the gateway itself -- stays the default run behavior. A first argument
	// that isn't a flag is a subcommand, and cobra owns the whole tree from
	// there (see newRootCmd), including rejecting a mistyped one; run()'s own
	// flags are still the stdlib flag package's.
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		root := newRootCmd()
		root.SetArgs(normalizeLegacyArgs(os.Args[1:]))
		if err := root.Execute(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// legacyLongFlag matches a Go-flag-style long option: a single dash, a name of
// more than one character, optionally =value. It deliberately does not match a
// one-character name (a real pflag shorthand, e.g. -h) or something that only
// looks flag-like (-5).
var legacyLongFlag = regexp.MustCompile(`^-[A-Za-z][-_A-Za-z0-9]+(=.*)?$`)

// normalizeLegacyArgs rewrites Go-flag-style single-dash long options into the
// double-dash form pflag requires: -json becomes --json.
//
// This binary necessarily speaks both dialects. The gateway's own flags are
// still the stdlib flag package's, where -wan and --wan are the same thing, so
// leaving `stats -json` to fail with pflag's "unknown shorthand flag: 'j'"
// (a single dash being a cluster of shorthands there) would put two
// incompatible conventions in one command line -- and would break the form the
// stats subcommand documented before it moved to cobra. Every previously
// documented invocation keeps working instead.
//
// Rewriting stops at a bare "--", which both packages treat as the
// end-of-flags terminator.
func normalizeLegacyArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i, a := range out {
		if a == "--" {
			break
		}
		if legacyLongFlag.MatchString(a) {
			out[i] = "-" + a
		}
	}
	return out
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
		b4Addr         = flag.String("b4", "", "B4 IPv6 address, our side of the DS-Lite softwire; if omitted, it is tracked dynamically from the WAN interface's kernel-chosen source toward the AFTR (RFC 6724) and re-selected when the WAN address changes (the DS-Lite B4-address change of RFC 7785)")
		aftrAddr       = flag.String("aftr", "", "AFTR IPv6 address; if omitted, discovered via DHCPv6 (RFC 3736 + RFC 6334)")
		wanDstMAC      = flag.String("wan-dst-mac", "", "fallback next-hop MAC on the WAN side, used only if FIB lookup can't resolve one")
		statsEvery     = flag.Duration("stats-interval", 10*time.Second, "how often to log datapath stats (0 disables)")
		requestPD      = flag.Bool("dhcpv6-pd", false, "request a delegated IPv6 prefix via DHCPv6-PD (RFC 3633) on the WAN interface and assign one /64 per -lan interface from it")
		ndProxy        = flag.Bool("ndproxy", false, "extend the WAN interface's own SLAAC /64 onto every -lan interface via RFC 4389 Neighbor Discovery Proxy, for ISPs that hand out a single WAN /64 with no DHCPv6-PD delegation (mutually exclusive with -dhcpv6-pd)")
		dnsProxyOn     = flag.Bool("dns-proxy", false, "run a DNS proxy (RFC 6333's B4 SHOULD) on every -lan interface's gateway IP, port 53/UDP+TCP, forwarding queries directly over IPv6 to -dns-server (or the DHCPv6-learned DNS servers, if -dns-server is omitted) instead of through the DS-Lite softwire")
		dhcpv4On       = flag.Bool("dhcpv4", false, "run a DHCPv4 server (RFC 2131) on every -lan interface, handing LAN clients an address from that interface's subnet (see -lan's optional /prefixlen, default /24), with the gateway IP as router and DNS (pair with -dns-proxy) and a DS-Lite-adjusted MTU")
		dhcpv4Lease    = flag.Duration("dhcpv4-lease", 12*time.Hour, "DHCPv4 lease duration handed to LAN clients (with -dhcpv4)")
		mssClamp       = flag.String("tcp-mss-clamp", "auto", "bound the MSS a TCP SYN crossing the softwire may advertise, so TCP never offers segments the softwire would have to fragment: \"auto\" tracks the softwire MTU (including a learned path MTU), \"off\" disables clamping, or give an explicit MSS in bytes")
		ipv6SwRSS      = flag.Bool("ipv6-sw-rss", false, "spread native-IPv6 forwarding-fastpath work across CPUs with a cpumap software-RSS stage; leave off when the NIC's hardware RSS already distributes flows (e.g. mlx4)")
		hb46ppVendorID = flag.String("hb46pp-vendor-id", defaultHB46PPVendorID, "HB46PP vendorid query parameter sent during provisioning discovery fallback (vendor OUI, optionally -suffix)")
		hb46ppProduct  = flag.String("hb46pp-product", defaultHB46PPProduct, "HB46PP product query parameter sent during provisioning discovery fallback")
		hb46ppVersion  = flag.String("hb46pp-version", defaultHB46PPVersion, "HB46PP version query parameter sent during provisioning discovery fallback (digits/underscores only)")
		pidFile        = flag.String("pidfile", "", "write our PID to this file once startup completes and remove it on exit, for a supervisor or test rig to track the instance")
		lans           cliconfig.LANSpecList
		dnsServersFlag cliconfig.AddrList
		dhcpv4DNSFlag  cliconfig.AddrList
	)
	flag.Var(&lans, "lan", "LAN interface as iface=gatewayIP[/prefixlen][,mtu] (repeatable, required at least once)")
	flag.Var(&dnsServersFlag, "dns-server", "upstream DNS server for -dns-proxy to forward to (repeatable, IPv6 recommended -- see -dns-proxy); defaults to the DNS servers learned via DHCPv6 during AFTR discovery if omitted")
	flag.Var(&dhcpv4DNSFlag, "dhcpv4-dns", "IPv4 DNS server to advertise to DHCPv4 clients (repeatable, with -dhcpv4); if unset, the -lan gateway IP is advertised when -dns-proxy is running to answer there, otherwise no DNS is advertised")
	flag.Parse()

	if *wanIface == "" || len(lans) == 0 {
		flag.Usage()
		return errors.New("missing required flags: -wan and at least one -lan")
	}
	if *requestPD && *ndProxy {
		flag.Usage()
		return errors.New("-dhcpv6-pd and -ndproxy are mutually exclusive WAN IPv6 provisioning models")
	}

	// -b4 omitted means dynamic: the B4 source is selected from the WAN's
	// kernel-chosen source toward the AFTR after the datapath attaches (see
	// resolveB4), and re-selected whenever the WAN address changes.
	dynamicB4 := *b4Addr == ""
	var staticB4 netip.Addr
	if !dynamicB4 {
		var err error
		staticB4, err = netip.ParseAddr(*b4Addr)
		if err != nil {
			return fmt.Errorf("parsing -b4: %w", err)
		}
	}
	dstMAC, err := cliconfig.ParseMAC(*wanDstMAC)
	if err != nil {
		return fmt.Errorf("parsing -wan-dst-mac: %w", err)
	}
	mssClampPolicy, err := cliconfig.ParseMSSClamp(*mssClamp)
	if err != nil {
		return fmt.Errorf("parsing -tcp-mss-clamp: %w", err)
	}
	// Every -dhcpv4 flag check that needs nothing but the flags themselves
	// belongs here, with the rest of the pure-flag validation, and not further
	// down next to the code that consumes them: everything below this point
	// can block indefinitely on the network (the DHCPv6-PD acquire and AFTR
	// discovery both retry until they succeed or ctx is cancelled), and a
	// misspelled flag must not be reported only after the network cooperates.
	for _, a := range dhcpv4DNSFlag {
		if !a.Is4() {
			return fmt.Errorf("-dhcpv4-dns %s must be an IPv4 address (DHCPv4 option 6 carries only IPv4 DNS servers)", a)
		}
	}
	if *dhcpv4On && *dhcpv4Lease < minDHCPv4Lease {
		return fmt.Errorf("-dhcpv4-lease must be at least %v (shorter leases don't yield valid T1/T2 renewal timers)", minDHCPv4Lease)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// A part of minuteman that gives up for good -- a supervision tree past
	// its restart intensity -- ends the whole of it through fail, as a signal
	// would, and run returns why.
	ctx, fail := context.WithCancelCause(ctx)
	defer fail(nil)
	// minuteman's supervision trees, started as applications as each is
	// needed (see startApps). They are stopped, in reverse order, by the
	// second deferred stopApps further down: after the rest of run's
	// goroutines -- the DHCPv6-PD maintenance releases its lease through
	// the DHCPv6 client on its way out -- and before what they drive is
	// closed. This one stops them on an earlier return.
	node := proc.NewNode("")
	apps, stopApps, err := startApps(ctx, fail, node)
	if err != nil {
		return err
	}
	defer stopApps()

	// The WAN's DHCPv6 client, which DHCPv6-PD and AFTR discovery exchange
	// through, when either runs.
	var dhcp dhcpv6.Exchanger
	if *requestPD || *aftrAddr == "" {
		if err := apps.Start(ctx, dhcpv6ClientApp(*wanIface)); err != nil {
			return err
		}
		dhcp = dhcpv6client.NewClient(node, *wanIface)
	}

	// The DHCPv6-PD lease is acquired before AFTR discovery, not with the rest
	// of the prefix-delegation setup further down, because on a network that
	// doesn't answer Information-Request this stateful exchange is the only
	// source of DNS servers -- and AFTR discovery's HB46PP fallback needs a
	// resolver to look anything up with (see discoverAFTROnce and §3 of
	// docs/rfc-compliance-backlog.md). Both exchanges go through the same
	// WAN DHCPv6 client, which runs them one at a time, so only their order
	// changes here, not their concurrency. Acquire blocks
	// until it succeeds or ctx is cancelled, exactly as it did when it ran
	// later; -dhcpv6-pd is an assertion that this network delegates a prefix,
	// so there is no useful CPE to bring up without one either way.
	var pdLease *prefixdelegation.Lease
	if *requestPD {
		pdLease, err = prefixdelegation.Acquire(ctx, dhcp)
		if err != nil {
			return fmt.Errorf("acquiring delegated prefix via DHCPv6-PD: %w", err)
		}
		// The prefix itself is logged by runPrefixDelegation further down,
		// along with the renewal timers; what's worth a line here is that the
		// delegation landed before AFTR discovery and what resolvers it can
		// lend it.
		log.Printf("DHCPv6-PD: delegation acquired on %s ahead of AFTR discovery (DNS servers: %v)", *wanIface, pdLease.DNSServers)
	}

	identity := hb46ppIdentity{vendorID: *hb46ppVendorID, product: *hb46ppProduct, version: *hb46ppVersion}
	disc, err := resolveAFTR(ctx, dhcp, *aftrAddr, *wanIface, identity, pdDNSServers(pdLease))
	if err != nil {
		return err
	}
	aftr := disc.aftr
	discoveredDNSServers := disc.dnsServers

	// Upstreams for -dns-proxy, most specific first: an explicit -dns-server
	// always wins; otherwise whatever AFTR discovery learned; otherwise the
	// PD lease's, which is all there is on a network with no stateless DHCPv6.
	dnsServers := discoveredDNSServers
	if len(dnsServers) == 0 {
		dnsServers = pdDNSServers(pdLease)
	}
	if len(dnsServersFlag) > 0 {
		dnsServers = dnsServersFlag
	}
	if *dnsProxyOn && len(dnsServers) == 0 {
		return errors.New("-dns-proxy needs at least one DNS server: none were learned via DHCPv6 (likely because -aftr was given directly, skipping DHCPv6 discovery, and -dhcpv6-pd is off or its server sent none) and none were given via -dns-server")
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

	// The in-XDP softwire fragmenter's companion veth pairs (RFC 6333 §5.3
	// outer-IPv6 fragmentation; see internal/fragpath for why the clones must
	// bounce through one large-MTU pair per fragment). Wired up before
	// SetB4Config sets frag_unit, so the datapath never engages the
	// fragmenter without the plumbing behind it. Fail-fast, matching the
	// slowpath tunnel's stance.
	fragVeths, err := fragpath.New()
	if err != nil {
		return fmt.Errorf("opening softwire fragmentation veth pairs: %w", err)
	}
	if err := fragVeths.Ensure(); err != nil {
		fragVeths.Close()
		return err
	}
	// Deferred (device teardown) so it runs after bgWG.Wait but before
	// dp.Close (defers are LIFO), the same ordering as tun.Close below. Note
	// this deletes the mm-frag* devices while dp.Close still holds the
	// xdp_softwire_frag* links (l.fragLinks) attached to them; that's benign
	// (Linux auto-detaches an XDP bpf_link on NETDEV_UNREGISTER, and a packet
	// arriving in that shutdown window just falls back and is dropped by the
	// kernel), but it is the reverse of detach-then-delete, so it's called out
	// here rather than left implicit.
	defer fragVeths.Close()
	if err := dp.EnableSoftwireFrag(fragVeths.RedirectIfindexes(), fragpath.FwdNames()); err != nil {
		return fmt.Errorf("enabling softwire fragmentation: %w", err)
	}
	log.Printf("softwire fragmentation: XDP outer-IPv6 fragmenter ready via %d mm-frag* veth pairs", fragpath.NumPairs)

	// Resolve the B4 softwire source. With -b4 it is the given static address;
	// without it, ask the kernel which source it would use toward the AFTR
	// (RFC 6724), retrying until the WAN's RA-learned route to the AFTR is back
	// (AttachWAN's forwarding flip purges it -- same reason SolicitRouters ran
	// above). The AFTR is already known here (resolveAFTR ran before the
	// datapath), so this can pick the exact source the softwire's own ip6tnl
	// would use.
	b4 := staticB4
	if dynamicB4 {
		b4, err = resolveB4(ctx, int(wanIfindex), aftr)
		if err != nil {
			return err
		}
		log.Printf("dynamic B4: kernel selected %s as the softwire source toward AFTR %s", b4, aftr)
	}

	if err := dp.SetB4Config(datapath.B4Config{
		B4Addr:       b4,
		AFTRAddr:     aftr,
		SrcMAC:       wanNetIface.HardwareAddr,
		DstMAC:       dstMAC,
		WANIfindex:   wanIfindex,
		WANMTU:       wanNetIface.MTU,
		FragMaxInner: fragpath.MaxInnerLen,
		TCPMSSClamp:  mssClampPolicy,
	}); err != nil {
		return fmt.Errorf("setting B4 config: %w", err)
	}

	// The companion ip6tnl slow path: what the XDP datapath's XDP_PASS of a
	// fragmentation case (oversized non-DF outbound, or a fragmented softwire
	// inbound) hands off to, so the kernel fragments/reassembles rather than the
	// datapath dropping (RFC 6333 §5.3). Created here, once the softwire
	// endpoints are known, for every run -- static or dynamic. Fail-fast: a home
	// CPE has no other IPv4 path. Its Close (device teardown) is deferred so it
	// runs after bgWG.Wait but before dp.Close (defers are LIFO), i.e. after the
	// rediscovery goroutine that may repoint it has drained.
	tun, err := slowpath.New(wanNetIface.MTU)
	if err != nil {
		return fmt.Errorf("opening softwire slow path: %w", err)
	}
	if err := tun.Ensure(b4, aftr); err != nil {
		tun.Close()
		return err
	}
	defer tun.Close()
	log.Printf("softwire slow path: ip6tnl %s <-> %s ready for fragmentation/reassembly", b4, aftr)

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
		rdnssByIface, err = startDNSProxy(ctx, apps, lans, dnsServers)
		if err != nil {
			return fmt.Errorf("-dns-proxy: %w", err)
		}
	}
	// The Router Advertisements of the LAN interfaces, when either model
	// gives them a prefix to advertise: an advertiser per interface
	// (internal/radvd), idle until DHCPv6-PD or NDProxy hands it one.
	var adv radvd.Advertiser
	if *requestPD || *ndProxy {
		lanIfaces := make([]string, len(lans))
		for i, spec := range lans {
			lanIfaces[i] = spec.Iface
		}
		if err := apps.Start(ctx, app("Router Advertisements", radvd.Spec(lanIfaces))); err != nil {
			return err
		}
		adv = radvd.NewAdvertiser(node)
	}
	if *requestPD {
		if err := runPrefixDelegation(ctx, dhcp, adv, *wanIface, pdLease, lans, rdnssByIface, &bgWG); err != nil {
			return err
		}
	}
	if *ndProxy {
		if err := runNDProxy(ctx, apps, adv, *wanIface, wanIfindex, lans, rdnssByIface, &bgWG); err != nil {
			return err
		}
	}
	if *dhcpv4On {
		if err := runDHCPv4(ctx, apps, lans, dhcpv4DNSFlag, *dnsProxyOn, wanNetIface.MTU, *dhcpv4Lease); err != nil {
			return err
		}
	}
	// The single owner of the live softwire endpoints (see
	// startSoftwireControl). It runs when the AFTR is dynamic (RFC 4242
	// periodic re-discovery, applying a changed AFTR live) and/or the B4 is
	// dynamic (watch the WAN source and hard-switch on a change -- the DS-Lite
	// B4-address change of RFC 7785). A fully static run (both -aftr and -b4
	// given) has nothing to track, so it's skipped.
	aftrDynamic := *aftrAddr == ""
	if aftrDynamic || dynamicB4 {
		closeNL, err := startSoftwireControl(ctx, apps, dhcp, dp, tun, b4, dynamicB4, aftrDynamic, *wanIface, wanIfindex, identity, disc, pdDNSServers(pdLease))
		if err != nil {
			return err
		}
		defer closeNL() // after the tree using it has stopped: see stopApps
	}
	// Follows the softwire path MTU the datapath learns from ICMPv6 Packet Too
	// Big messages about its own tunnel packets, applying it to the fragment
	// size and the companion ip6tnl (RFC 2473 §8/§6.7). Always on: a narrower
	// link somewhere along the B4<->AFTR path is not a configuration, and
	// nothing happens at all until one is actually reported.
	watchTunnelPMTU(ctx, dp, tun, wanNetIface.MTU, &bgWG)
	defer stopApps() // runs second: see where apps start
	defer bgWG.Wait()

	// Written only now, after every fail-fast startup step above, so the
	// file's existence means "up", not "starting".
	if *pidFile != "" {
		if err := os.WriteFile(*pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
			return fmt.Errorf("writing -pidfile: %w", err)
		}
		defer os.Remove(*pidFile)
	}

	logStatsUntilDone(ctx, dp, *statsEvery)
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// pdDNSServers returns the DNS servers a DHCPv6-PD lease carried, or nil
// when -dhcpv6-pd is off (lease == nil) or the delegating server sent none.
// It exists so callers can pass "whatever PD learned, if anything" without
// each of them nil-checking the lease.
func pdDNSServers(lease *prefixdelegation.Lease) []netip.Addr {
	if lease == nil {
		return nil
	}
	return lease.DNSServers
}

// runPrefixDelegation takes the already-acquired lease (run() acquires it
// early, before AFTR discovery, so its DNS servers can feed the HB46PP
// fallback -- see the call site), assigns the LAN addresses it carves from
// it and starts advertising each carved /64 to LAN clients via Router
// Advertisements (see reconcileAndLog), and starts the background
// lease-maintenance goroutine that keeps renewing it, registering that
// goroutine on wg so callers can wait for its shutdown-triggered Release
// (and every RA worker's shutdown-triggered final RouterLifetime=0
// advertisement) to finish before exiting. rdnssByIface is forwarded to
// lanprefix.NewRAManager (see its own doc) -- it's the map of link-local
// addresses startDNSProxy actually bound, so RDNSS is advertised only where
// a DNS proxy is really listening.
func runPrefixDelegation(ctx context.Context, dhcp dhcpv6.Exchanger, adv radvd.Advertiser, wanIface string, lease *prefixdelegation.Lease, lans cliconfig.LANSpecList, rdnssByIface map[string]netip.Addr, wg *sync.WaitGroup) error {
	lanIfaces := make([]string, len(lans))
	for i, spec := range lans {
		lanIfaces[i] = spec.Iface
	}

	raMgr := lanprefix.NewRAManager(adv, rdnssByIface)
	var assigned []lanprefix.Assignment
	reconcileAndLog := func(l *prefixdelegation.Lease) {
		var err error
		p := l.Prefixes[0]
		// The renewal timers are worth a line of their own: they may be
		// ones minuteman derived rather than ones the server sent (RFC
		// 9915 §14.2 leaves them to the client when the server sends 0),
		// so this is the only place an operator can see what the lease is
		// actually running on.
		log.Printf("DHCPv6-PD lease on %s: prefix %s, renew in %s, rebind in %s", wanIface, p.Prefix, l.T1, l.T2)
		assigned, err = lanprefix.Reconcile(p.Prefix, p.ValidLifetime, p.PreferredLifetime, lanIfaces, assigned)
		if err != nil {
			log.Printf("reconciling LAN addresses: %v", err)
		}
		for _, a := range assigned {
			log.Printf("assigned %s to %s (from delegated prefix %s)", a.Address, a.Iface, l.Prefixes[0].Prefix)
		}
		raMgr.Sync(assigned)
	}
	reconcileAndLog(lease) // initial assignment, before minuteman is considered "up"

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := prefixdelegation.Maintain(ctx, dhcp, lease, reconcileAndLog); err != nil {
			log.Printf("DHCPv6-PD maintenance loop ended unexpectedly: %v", err)
		}
	}()
	return nil
}

// runNDProxy runs the -ndproxy CPE model: internal/ndppd's tree, started as
// an application, answering WAN-side Neighbor Solicitations on wanIface for
// LAN hosts it actively verifies exist and installing their host routes
// (internal/wanextend.HostRoutes); then internal/wanextend.Serve, learning
// the WAN interface's own SLAAC /64, re-advertising it on every -lan
// interface with the On-Link flag cleared (see routeradvert.Config.OnLink's
// doc) and keeping that advertisement in sync if the WAN prefix later
// changes. wanextend.Serve registers its watch goroutine on wg, so run()
// waits for it before returning. rdnssByIface is forwarded to
// wanextend.Serve (see its own doc) -- it's the map of link-local addresses
// startDNSProxy actually bound, so RDNSS is advertised only where a DNS
// proxy is really listening.
func runNDProxy(ctx context.Context, apps *application.Running, adv radvd.Advertiser, wanIface string, wanIfindex uint32, lans cliconfig.LANSpecList, rdnssByIface map[string]netip.Addr, wg *sync.WaitGroup) error {
	lanIfaces := make([]string, len(lans))
	for i, spec := range lans {
		lanIfaces[i] = spec.Iface
	}
	spec := ndppd.Spec(ndppd.Config{
		WAN:  wanIface,
		LANs: lanIfaces,
		OpenRoutes: func() (ndppd.Routes, error) {
			r, err := wanextend.NewHostRoutes()
			if err != nil {
				return nil, err
			}
			return r, nil
		},
	})
	if err := apps.Start(ctx, app("NDProxy", spec)); err != nil {
		return fmt.Errorf("starting NDProxy: %w", err)
	}
	return wanextend.Serve(ctx, int(wanIfindex), lanIfaces, rdnssByIface, adv, wg)
}

// startDNSProxy starts internal/dnsproxy's supervision tree on every -lan
// interface's IPv4 gateway IP and its own link-local IPv6 address, and
// returns a map of -lan interface -> the link-local address it bound there.
// Called, and its success checked, *before* runPrefixDelegation/runNDProxy:
// those advertise exactly the addresses in that returned map as RDNSS entries
// (RFC 8106), so an RA can never promise a DNS server the proxy didn't
// actually bind -- the tree's start returns only once every listener has
// bound (fail-fast), as internal/dhcpv4server's does. A LAN link-local still DAD-tentative is waited out by the
// listener itself (see internal/dnsproxy). A -lan interface with no
// link-local address at all is logged and left out of the map (no RDNSS for
// it), while its IPv4 listener still starts.
func startDNSProxy(ctx context.Context, apps *application.Running, lans cliconfig.LANSpecList, dnsServers []netip.Addr) (map[string]netip.Addr, error) {
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

	spec, err := dnsproxy.Spec(dnsproxy.Config{ListenAddrs: listenAddrs, Upstreams: dnsproxy.Upstreams(dnsServers)})
	if err != nil {
		return nil, err
	}
	if err := apps.Start(ctx, app("DNS proxy", spec)); err != nil {
		return nil, err
	}
	log.Printf("DNS proxy: listening on %v, forwarding to %v", listenAddrs, dnsServers)
	return rdnssByIface, nil
}

// runDHCPv4 builds a pkg/dhcpv4.InterfaceConfig for every -lan interface,
// and starts internal/dhcpv4server's tree as an application of apps; the
// start validates every pool and opens every socket, so an invalid subnet or
// a socket failure fails run() rather than surfacing only in a log line. Each interface serves its own subnet (from -lan's /prefixlen),
// offers its gateway IP as router, and advertises an interface MTU sized for
// the DS-Lite softwire: the -lan MTU if set, else the WAN MTU minus the
// 40-byte tunnel overhead (dropped if that falls below the IPv4 minimum). A
// -lan without an IPv4 subnet (an IPv6-only gateway) is rejected.
//
// The DNS server offered (option 6) is dnsOverride (-dhcpv4-dns) if given,
// else this CPE's gateway when -dns-proxy is running to answer at it; with
// neither, no DNS is advertised at all rather than pointing clients at a port
// nothing listens on.
func runDHCPv4(ctx context.Context, apps *application.Running, lans cliconfig.LANSpecList, dnsOverride []netip.Addr, dnsProxyOn bool, wanMTU int, lease time.Duration) error {
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

	spec, err := dhcpv4server.Spec(cfgs)
	if err != nil {
		return err
	}
	if err := apps.Start(ctx, app("DHCPv4 server", spec)); err != nil {
		return fmt.Errorf("starting DHCPv4 server: %w", err)
	}
	return nil
}

// aftrDiscovery is one AFTR discovery outcome, carrying what the periodic
// re-discovery loop needs to pace itself and to switch the datapath.
type aftrDiscovery struct {
	aftr       netip.Addr
	dnsServers []netip.Addr  // RFC 3646 servers from the DHCPv6 Reply (for -dns-proxy); nil for a static -aftr
	refresh    time.Duration // RFC 4242 / HB46PP ttl; 0 for a static -aftr (no re-discovery)
	// hb46ppToken is the token an HB46PP provisioning response asked us to
	// echo on the next request (v6mig-1 §3.3); "" on the DHCPv6/DNS path or
	// when the server sent none.
	hb46ppToken string
}

// b4ResolveRetryInterval is how often resolveB4 re-asks the kernel for the B4
// source at startup while the WAN's route to the AFTR is still absent (the
// AttachWAN forwarding flip purged it; SolicitRouters is bringing it back).
const b4ResolveRetryInterval = time.Second

// resolveB4 asks the kernel which local IPv6 address it would use as the
// softwire source toward aftr out the WAN interface (RFC 6724 selection, via
// pkg/netlink.SourceForDest), retrying every b4ResolveRetryInterval until an
// answer is available. At startup the WAN's RA-learned route to the AFTR is
// briefly gone (AttachWAN's forwarding-enable purge; SolicitRouters restores
// it), so the first few queries return no source -- that's expected, not fatal.
// Nor is a source that isn't global (see softwirectl.UsableB4): right after
// AttachWAN bounces the link, the WAN's own global address is DAD-tentative
// again, and until it is usable the kernel answers with the link-local one,
// which no AFTR can reach. Blocks until it resolves or ctx is cancelled.
func resolveB4(ctx context.Context, wanIfindex int, aftr netip.Addr) (netip.Addr, error) {
	nl, err := netlink.Open()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("opening netlink socket for B4 selection: %w", err)
	}
	defer nl.Close()

	loggedNoRoute, loggedNotGlobal := false, false
	for {
		src, ok, err := nl.SourceForDest(wanIfindex, aftr)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("selecting B4 source toward %s: %w", aftr, err)
		}
		switch {
		case ok && softwirectl.UsableB4(src):
			return src, nil
		case ok && !loggedNotGlobal:
			log.Printf("dynamic B4: kernel offers %s toward AFTR %s, not a global address; waiting for the WAN's own (likely still DAD-tentative)", src, aftr)
			loggedNotGlobal = true
		case !ok && !loggedNoRoute:
			log.Printf("dynamic B4: waiting for the WAN's route to AFTR %s (RA-learned route not back yet)", aftr)
			loggedNoRoute = true
		}
		select {
		case <-ctx.Done():
			return netip.Addr{}, ctx.Err()
		case <-time.After(b4ResolveRetryInterval):
		}
	}
}

// resolveAFTR returns aftrFlag parsed as an IPv6 address if non-empty,
// otherwise discovers the AFTR live (see discoverAFTROnce), retrying on
// failure with the HB46PP spec's backoff for the failure class. Discovery
// blocks until it succeeds or ctx is cancelled -- there's no working DS-Lite
// path without an AFTR address, so waiting (with visible retry behavior) is
// preferable to an arbitrary timeout.
//
// Every discovery failure is retried, including a persistent one (a malformed
// OPTION_AFTR_NAME, or an AFTR name that never resolves): minuteman stays up
// (its native-IPv6 forwarding keeps working) and logs each attempt rather than
// exiting. Only ctx cancellation ends the loop. This is deliberately more
// tolerant than exiting on a hard error would be -- restarting wouldn't fix an
// ISP-side misconfiguration, and the visible retry log surfaces it either way.
//
// fallbackDNS is the resolver set to hand HB46PP when the Information-Request
// draws no reply at all and so yields none of its own -- in practice the DNS
// servers the DHCPv6-PD exchange learned (see run()'s ordering). It may be
// nil, in which case HB46PP falls back to the system resolver.
func resolveAFTR(ctx context.Context, dhcp dhcpv6.Exchanger, aftrFlag, wanIface string, identity hb46ppIdentity, fallbackDNS []netip.Addr) (aftrDiscovery, error) {
	if aftrFlag != "" {
		aftr, err := netip.ParseAddr(aftrFlag)
		if err != nil {
			return aftrDiscovery{}, fmt.Errorf("parsing -aftr: %w", err)
		}
		return aftrDiscovery{aftr: aftr}, nil
	}

	log.Printf("no -aftr given, discovering AFTR via DHCPv6 on %s", wanIface)
	for {
		disc, err := discoverAFTROnce(ctx, dhcp, wanIface, identity, "", fallbackDNS)
		if err == nil {
			return disc, nil
		}
		if ctx.Err() != nil {
			return aftrDiscovery{}, ctx.Err()
		}

		delay := retryDelayFor(err)
		log.Printf("AFTR discovery failed: %v (retrying in %v)", err, delay.Round(time.Second))
		select {
		case <-ctx.Done():
			return aftrDiscovery{}, ctx.Err()
		case <-time.After(delay):
		}
	}
}

// retryDelayFor is hb46pp.RetryDelay with one local exception: an attempt
// whose Information-Request went unanswered (aftrdiscovery.ErrNoReply in the
// chain, put there by discoverAFTROnce) is capped at noReplyRetryCap, because
// the HB46PP verdict that produced the delay was reached without any evidence
// from DHCPv6 about what kind of network this is.
func retryDelayFor(err error) time.Duration {
	delay := hb46pp.RetryDelay(err)
	if errors.Is(err, aftrdiscovery.ErrNoReply) && delay > noReplyRetryCap {
		return noReplyRetryCap
	}
	return delay
}

// discoverAFTROnce runs one DHCPv6-then-HB46PP discovery attempt on wanIface
// (RFC 3736 Information-Request + RFC 6334 OPTION_AFTR_NAME, resolved via
// DNS; falling back to HB46PP provisioning of the dslite capability).
// prevToken, if set, is echoed on the HB46PP request (v6mig-1 §3.3).
//
// There are two distinct routes to the HB46PP fallback, and they differ in
// where its resolvers come from:
//
//   - The Reply carried no AFTR-Name (aftrdiscovery.ErrNoAFTRName): the ISP
//     speaks stateless DHCPv6 but names no AFTR through it, so HB46PP gets the
//     DNS servers that same Reply carried.
//   - Nothing answered within informationRequestTimeout
//     (aftrdiscovery.ErrNoReply): the network most likely doesn't implement
//     stateless DHCPv6 at all, and nothing was learned -- so HB46PP gets
//     fallbackDNS, which run() sources from the DHCPv6-PD exchange. That error
//     is kept in the chain of whatever HB46PP then returns, for retryDelayFor.
func discoverAFTROnce(ctx context.Context, dhcp dhcpv6.Exchanger, wanIface string, identity hb46ppIdentity, prevToken string, fallbackDNS []netip.Addr) (aftrDiscovery, error) {
	result, err := aftrdiscovery.Discover(ctx, dhcp, informationRequestTimeout)
	switch {
	case err == nil:
		log.Printf("discovered AFTR %s -> %s (DNS servers: %v)", result.AFTRName, result.AFTRAddr, result.DNSServers)
		return aftrDiscovery{
			aftr:       result.AFTRAddr,
			dnsServers: result.DNSServers,
			refresh:    result.RefreshInterval,
		}, nil

	case errors.Is(err, aftrdiscovery.ErrNoAFTRName):
		// result is aftrdiscovery's documented partial result here: the Reply
		// had DNS servers but no AFTR-Name.
		log.Printf("DHCPv6 Reply carried no AFTR-Name, trying HB46PP provisioning (DNS servers: %v)", result.DNSServers)
		return discoverViaHB46PP(ctx, result.DNSServers, identity, prevToken)

	case errors.Is(err, aftrdiscovery.ErrNoReply):
		// No result at all here -- not even DNS servers -- so fallbackDNS is
		// the only resolver set HB46PP can be given.
		log.Printf("no reply to the DHCPv6 information-request on %s within %v, trying HB46PP provisioning (DNS servers: %v)",
			wanIface, informationRequestTimeout, fallbackDNS)
		disc, hbErr := discoverViaHB46PP(ctx, fallbackDNS, identity, prevToken)
		if hbErr != nil {
			return aftrDiscovery{}, fmt.Errorf("%w (reached because %w)", hbErr, err)
		}
		return disc, nil

	default:
		return aftrDiscovery{}, fmt.Errorf("discovering AFTR: %w", err)
	}
}

// discoverViaHB46PP runs one HB46PP provisioning exchange advertising the
// dslite capability (echoing prevToken if set) and returns the AFTR it
// yields plus the metadata the re-discovery loop needs. dnsServers (from the
// DHCPv6 Reply) are the VNE's own resolvers, which is what the 4over6.info
// TXT lookup must go through.
func discoverViaHB46PP(ctx context.Context, dnsServers []netip.Addr, identity hb46ppIdentity, prevToken string) (aftrDiscovery, error) {
	result, err := hb46pp.Discover(ctx, hb46pp.Config{
		Client: hb46pp.ClientInfo{
			VendorID:     identity.vendorID,
			Product:      identity.product,
			Version:      identity.version,
			Capabilities: []string{"dslite"},
			Token:        prevToken,
		},
		DNSServers: dnsServers,
	})
	if err != nil {
		return aftrDiscovery{}, err
	}
	if !result.AFTRAddr.IsValid() {
		return aftrDiscovery{}, fmt.Errorf("provisioning server returned no DS-Lite parameters (offered order: %v)", result.Provisioning.Order)
	}
	log.Printf("HB46PP: provisioned by %q (%s): AFTR %s -> %s (refresh in %v)",
		result.Provisioning.EnablerName, result.Provisioning.ServiceName,
		result.AFTRName, result.AFTRAddr, result.RefreshInterval)
	return aftrDiscovery{
		aftr:        result.AFTRAddr,
		dnsServers:  dnsServers,
		refresh:     result.RefreshInterval,
		hb46ppToken: result.Provisioning.Token,
	}, nil
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

	// A LAN whose MTU exceeds the in-XDP fragmenter's clone-admission ceiling
	// lets clients emit an inner packet too big for outer-IPv6 fragmentation,
	// which then silently falls to the kernel ip6tnl (inner-IPv4 fragmentation,
	// not RFC 6333 §5.3-conformant — see docs/rfc-compliance-backlog.md §3).
	// Surface it once at startup so it's actionable, not discovered via counters.
	if mtu > fragpath.MaxInnerLen {
		log.Printf("warning: LAN %s MTU %d exceeds the softwire fragmenter's ceiling (%d); oversized traffic from this LAN uses the non-§5.3 ip6tnl fallback (EncapFragSlow)",
			spec.Iface, mtu, fragpath.MaxInnerLen)
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
