# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project purpose

Minuteman is a high-performance CPE (Customer Premises Equipment) gateway for home use, built on XDP/eBPF.
The goal is a practical, production-usable system covering the functionality a home gateway needs — including
DHCPv6 Prefix Delegation (PD) and AFTR (DS-Lite) resolution — on top of an XDP-based fast-path datapath.

## Current state

The DS-Lite (RFC 6333) B4-element datapath is implemented and attaches/runs against real interfaces
(verified against veth pairs: XDP programs load, pass the kernel verifier, and process live traffic).
AFTR discovery is also implemented: a from-scratch, stdlib-only DHCPv6 client (RFC 3736 Information-Request
+ RFC 6334 `OPTION_AFTR_NAME`, resolved via DNS) runs in-process when `-aftr` is omitted — no external
DHCP/DNS client daemon is spawned, consistent with the project's no-sidecar goal. When the DHCPv6 Reply
carries no AFTR-Name, discovery now falls back to HB46PP (the JAIPA-standardized "HTTP-Based IPv4 over
IPv6 Provisioning Protocol", `pkg/hb46pp` — see Architecture below): the fallback advertises
`capability=dslite` and feeds the resulting `dslite.aftr` into the same DS-Lite setup, so minuteman works
against both DHCPv6-provisioning and HB46PP-provisioning VNEs with no per-provider configuration. DHCPv6 Prefix Delegation
(RFC 3633) is also implemented behind `-dhcpv6-pd`: `pkg/dhcpv6` grew a generic stateful exchange (Solicit/
Request/Renew/Rebind/Release) that `pkg/prefixdelegation` drives to acquire and maintain a delegated prefix,
and `internal/lanprefix` carves one `/64` per `-lan` interface from it and assigns it via hand-rolled
netlink (`golang.org/x/sys/unix`, no netlink library or `ip` exec). `internal/lanprefix` also now drives
Router Advertisements (RFC 4861) out each `-lan` interface via the new `pkg/routeradvert` package, so LAN
clients can SLAAC an address out of the assigned `/64` themselves — LAN clients get both the DS-Lite IPv4
path and native IPv6 out of the delegated prefix. `internal/` holds `cliconfig` (CLI flag parsing) and
`lanprefix` (DHCPv6-PD LAN policy, including RA serving); `pkg/dhcpv6`/`pkg/aftrdiscovery`/`pkg/hb46pp`/
`pkg/prefixdelegation`/`pkg/routeradvert` are the reusable protocol packages.

Not yet implemented: NDProxy (RFC 4389). The current model assumes the ISP supports DHCPv6-PD and
delegates a prefix distinct from the WAN link's own — real IPv6 routing between WAN and LAN (plain
kernel forwarding, since `xdp_dslite_encap` passes all non-IPv4 traffic through untouched) is then
sufficient, no proxying needed. Some ISPs/configurations instead hand out only a single `/64` on the WAN
link with no PD, and expect the CPE to extend that same `/64` to the LAN via NDProxy (answering Neighbor
Solicitations on the WAN link on behalf of LAN hosts). Supporting that model would need a new package
(reusing `pkg/routeradvert/transport.go`'s raw ICMPv6 socket plumbing) plus, unlike RA sending, a new
piece of state this project hasn't needed before: learning which addresses actually exist on the LAN
(via NS/NA snooping) so the WAN-side proxy replies only for real hosts.

Also not yet implemented: the migration technologies other than DS-Lite that an HB46PP response can
describe (`map_e`/`map_t`/`lw4o6`/`464xlat`/`ipip`). `pkg/hb46pp` already decodes the response's
`order`-ranked technology list and preserves those technologies' parameter objects raw
(`json.RawMessage` fields on `hb46pp.Provisioning`), so implementing one of them means adding its typed
parameter struct there, its datapath, and extending `cmd/minuteman`'s policy beyond the current
dslite-only capability request. Also not acted on yet: periodic re-discovery — both
`aftrdiscovery.Result` and `hb46pp.Result` report their refresh interval (RFC 4242's, and HB46PP's
`ttl`/20-24h default, respectively) but `cmd/minuteman` discovers once at startup and never re-runs
discovery.

## Build commands

Building requires a live kernel BTF file and the `bpftool`/`clang` toolchain.

```sh
make            # regenerates BPF Go bindings, then builds bin/minuteman
make build-bpf   # generates bpf/vmlinux.h if missing, then runs `go generate ./pkg/...` (bpf2go)
make clean        # removes bpf/vmlinux.h, bin/*, *.o, and the generated pkg/datapath/bpf_x86_* files
```

Notes on the build:
- `vmlinux.h` is generated from `/sys/kernel/btf/vmlinux` via `bpftool btf dump file ... format c` and is
  gitignored; delete it (or `make clean`) to force regeneration against the current kernel's BTF.
- `make`/`make build-bpf` runs bpf2go (`pkg/datapath/gen.go`'s `//go:generate` directive), which invokes clang
  to compile `bpf/datapath.bpf.c` and embeds the resulting object into generated Go source
  (`pkg/datapath/bpf_x86_bpfel.go` + `.o`, gitignored per `bpf_x86_*.go`/`*.o`). Regenerate manually with
  `go generate ./pkg/datapath/...` when editing the BPF C sources directly.
- Cross-compilation vars: `GOOS`, `GOARCH` (default `linux`/`amd64`), `CGO_ENABLED=0` by default.
- Binary output: `bin/minuteman`.
- Loading the compiled program into the kernel (e.g. running `minuteman`, or manually via `bpftool prog load`)
  requires `CAP_BPF`/`CAP_NET_ADMIN` (root, or equivalent capabilities) and a locked-memory rlimit high enough
  for the maps — `pkg/datapath.Load()` calls `rlimit.RemoveMemlock()` to handle the latter.

There is no automated test suite, linter config, or CI wired up yet. There is a manual netns integration
rig — see "Testing: netns DS-Lite rig" below.

## Testing: netns DS-Lite rig

`test/netns/` builds a 5-namespace RFC 6333 topology (`mm-host` LAN client → `mm-cpe` running minuteman as
the B4 → `mm-isp` IPv6 access network → `mm-aftr` AFTR simulator → `mm-inet` simulated public IPv4 internet)
to exercise the datapath end-to-end without physical hardware:

```sh
sudo ./test/netns/setup.sh       # builds the namespaces/veths/routing/NAT
sudo ./test/netns/run-cpe.sh     # runs bin/minuteman as the B4 inside mm-cpe (discovers the AFTR live)
sudo ./test/netns/smoketest.sh   # starts minuteman itself + pings/curls end-to-end
sudo ./test/netns/teardown.sh    # tears everything down (always safe to re-run)
```

`common.sh` holds every namespace/interface/address name in one place; the other scripts source it rather
than repeating the topology. `mm-isp` runs dnsmasq for RA + DNS and Kea for DHCPv6 (stateless RFC 3736
service and DHCPv6-PD — only one process can bind port 547, and dnsmasq has no PD support). How the AFTR's
address is published is selectable at setup time via `MM_AFTR_DISCOVERY`:
- `dhcpv6` (default): Kea serves a real RFC 6334 `OPTION_AFTR_NAME` (hand-encoded in `common.sh`'s
  `encode_dns_name`, since neither server has a built-in encoder for it) that dnsmasq's DNS resolves to the
  AFTR's tunnel address, exercising `pkg/aftrdiscovery`.
- `hb46pp`: Kea withholds option 64, so minuteman's discovery falls back to HB46PP — dnsmasq serves the
  `4over6.info` discovery TXT record pointing at a `python3 -m http.server` in `mm-isp` that serves the
  provisioning JSON as a static `rule.cgi` file (python's handler ignores the query string, so minuteman's
  real query parameters are accepted and simply unread), exercising `pkg/hb46pp` end-to-end. `setup.sh`
  records the mode in `$RUNDIR/aftr-discovery-mode` so `smoketest.sh` asserts the matching discovery checks.

`run-cpe.sh` and `smoketest.sh` deliberately omit `-aftr` so minuteman discovers it live against the rig —
pass `-aftr <addr>` as an extra argument to either script to override with a static address instead.

Two things worth knowing if you touch these scripts:
- `mm-cpe` needs both `net.ipv4.ip_forward=1` and `net.ipv6.conf.all.forwarding=1`, or `bpf_fib_lookup()` in
  the datapath returns `BPF_FIB_LKUP_RET_FWD_DISABLED` for every packet and nothing gets encapsulated;
  `net.ipv6.conf.<if>.accept_ra=2` is then needed on top so RA/SLAAC still works with forwarding on.
  `setup.sh` no longer sets these itself — `pkg/datapath.Loader.AttachWAN` does (see Architecture below), so
  they're applied whenever minuteman runs, not just inside this test rig.
- mm-isp's dnsmasq must be started, and mm-cpe's WAN link brought up, in that order — Linux only retries
  Router Solicitation a few times right after an interface comes up, so if the RA server isn't listening yet
  the CPE gives up and never gets a default route; `setup.sh` sequences this deliberately, don't reorder it.
  Likewise the `dhcp-range=::,constructor:<iface>,ra-only` form is required (not bare `::`) or dnsmasq
  never actually replies to Router Solicitations despite logging that RA is enabled.

The AFTR's decap step uses a kernel `ip6tnl` (mode `ipip6`) device, which needs the `ip6_tunnel` module.
`setup.sh` checks for it up front with a specific diagnostic for the common Arch situation where a kernel
package upgrade has replaced `/lib/modules/<old-version>/` before a reboot, leaving the currently *running*
kernel without a matching module directory (`uname -r` disagrees with what's on disk) — reboot to fix that.
The full smoketest (AFTR discovery, DHCPv6-PD + RA/SLAAC, and the DS-Lite data path end-to-end through
the AFTR's decap+NAPT44 to the simulated internet and back, ICMP and TCP) has been verified passing from
a fresh setup in both discovery modes — `dhcpv6` and `hb46pp`.

## Code style

- C (eBPF) formatting is enforced via `.clang-format`: 4-space indent, right-aligned pointers, 90-column limit,
  custom brace wrapping (opening brace on its own line only after function definitions). Run `clang-format` on
  `bpf/*.bpf.c`/`bpf/*.h` before committing.
- Go module path is `github.com/shun159/miniteman` (note: `miniteman`, not `minuteman` — a pre-existing typo in
  `go.mod`; match it exactly in imports), building on Go 1.26.2.

## Architecture

- **`bpf/datapath.bpf.c`** — the DS-Lite XDP datapath. Two independently attachable programs:
  - `xdp_dslite_encap` (`SEC("xdp")`, attach to LAN interfaces): parses inbound IPv4, bypasses DS-Lite for
    LAN-local traffic (`is_local_gateway_dst` / `is_local_lan_route`, via `bpf_fib_lookup`), checks WAN path MTU
    accounting for the 40-byte IPv6 encap overhead (`TUNNEL_L3_OVERHEAD`), replies with a plain ICMPv4
    Fragmentation-Needed via `XDP_TX` when needed (`send_plain_icmp_frag_needed` — untunneled, since the LAN
    sender is directly reachable on the ingress interface), then wraps the packet in an outer
    Ethernet+IPv6(nexthdr=`IPPROTO_IPIP`) header and redirects it out the WAN ifindex via the `tx_ports`
    `DEVMAP_HASH`.
  - `xdp_dslite_decap` (`SEC("xdp")`, attach to the WAN interface) / `xdp_dslite_decap_cpu` (`SEC("xdp/cpumap")`
    second-stage variant): validates the outer IPv6 header matches the configured AFTR/B4 pair
    (`is_expected_dslite_peer`), optionally fans decap work out across CPUs first
    (`maybe_redirect_to_cpu` + the `cpu_map`/`fanout_*` maps, gated by `fanout_config.enabled`), strips the
    IPv6 header, resolves the LAN egress interface via `bpf_fib_lookup`, and — if the egress path MTU is too
    small — replies with an ICMPv4 Fragmentation-Needed re-encapsulated back through the softwire
    (`send_dslite_icmp_frag_needed`, since the original IPv4 sender is only reachable via the AFTR).
  - Config is held in BPF maps, not hardcoded: `b4_config_map` (single-entry `ARRAY`: B4/AFTR IPv6 addresses,
    fallback WAN MACs, WAN ifindex) and `lan_configs` (`HASH` keyed by LAN ifindex: gateway IPv4, inner MTU).
    Per-path counters live in the `stats` `PERCPU_ARRAY` (see `enum stat_id`).
  - **`bpf/datapath_helpers.h`** — shared low-level helpers (checksum fold/compute, TTL decrement with
    incremental checksum update, L2(+VLAN)/IPv4/IPv6 header parsing with bounds checks, IPv6 address
    comparison, ICMP Fragmentation-Needed message construction in both plain and DS-Lite-tunneled form).
  - **`bpf/uapi/linux/*.h`** — vendored kernel UAPI headers providing `#define` constants (`ETH_P_*`, `IP_DF`,
    `ICMP_*`) that the BTF-derived `bpf/vmlinux.h` (struct/union/enum definitions only, no macros) doesn't
    carry. `vmlinux.h` and these uapi headers are complementary: struct/type layouts come from BTF, numeric
    constants come from the vendored headers.
- **`pkg/datapath/`** — the only package that touches `cilium/ebpf` or BPF map/program layouts; wraps loading
  in a `Loader` type:
  - `gen.go` — the `//go:generate bpf2go` directive (source of truth for how the object is built/embedded).
  - `loader.go` — `Load()`, `AttachWAN(iface string)`, `AttachLAN(iface string)`, `Close()`. `AttachWAN` also
    calls `sysctl.go`'s `configureWANSysctls` (plain `/proc/sys/net/...` file writes, no netlink/`ip` exec
    needed) to enable `net.ipv4.ip_forward`/`net.ipv6.conf.all.forwarding` (both process-wide — required by
    both encap's and decap's FIB lookups regardless of which interface they're attached to, or
    `bpf_fib_lookup()` returns `BPF_FIB_LKUP_RET_FWD_DISABLED`) and re-enable `accept_ra=2` on the WAN
    interface specifically (needed to keep accepting Router Advertisements once forwarding is on, so
    SLAAC/RA-installed default routes keep getting refreshed) — callers don't need to configure this
    externally. `accept_ra=2` is deliberately written *before* forwarding, but the forwarding 0→1
    transition still makes the kernel purge every already-RA-learned default route regardless
    (`rt6_purge_dflt_routers`), leaving the WAN with no route to the AFTR until the ISP's next unsolicited
    RA — which is why `cmd/minuteman` fires `pkg/routeradvert.SolicitRouters` right after `AttachWAN` (the
    fix for an end-to-end failure actually observed in the netns rig: encap's FIB lookup failed for every
    packet until dnsmasq's next periodic RA, minutes later).
  - `config.go` — `SetB4Config(B4Config)`, `SetLANConfig(ifindex uint32, LANConfig)`; also registers each
    attached ifindex as a valid `bpf_redirect_map()` target in `tx_ports` (self-mapped ifindex → ifindex).
  - `stats.go` — `Stats()` sums the `PERCPU_ARRAY` counters across CPUs into a plain `Stats` struct. The
    field/index order (`statID` in `stats.go`) must be kept manually in sync with `enum stat_id` in the C
    source — bpf2go can't export a Go enum here because `enum stat_id` never appears as a stored map value
    type in the BTF (only as inlined integer constants), so `-type stat_id` finds nothing.
  - IPv4/IPv6 addresses are exchanged with the BPF maps as `netip.Addr` at the API boundary; internally they're
    converted to the `in6_u.u6_addr8`/big-endian-`uint32` layouts the generated `bpfB4Config`/`bpfLanConfig`
    structs expect (see `config.go`).
- **`pkg/dhcpv6/`** — generic, stdlib-only DHCPv6 client covering both RFC 3736 stateless service and the
  RFC 3315 stateful exchanges a PD client needs. `duid.go` (DUID-LL from a MAC — regenerated fresh each run
  rather than persisted, since it's a pure function of hardware-type+MAC), `message.go`/`options.go` (wire
  codec; option *codes* for options a consuming package decodes itself, e.g. `OptionIAPD`/`OptionIAPrefix`/
  `OptionAFTRName`, live here as bare constants, but their actual decoding does not), `retransmit.go` (pure
  RFC 3315 §5.5/§14 timing for every exchange — initial jitter via `randDelay`, then backoff capped at each
  exchange's MRT with jitter re-applied around the cap forever, *not* clamped to a fixed value; Request/
  Release additionally have a maximum retransmission *count*), `transport.go` (`ListenUDP`, never
  `DialUDP`, bound to the WAN interface's link-local address — a connected socket would drop the server's
  unicast Reply; `sendAndWait` takes the expected reply `MessageType` since Solicit expects an Advertise,
  not a Reply), `client.go`'s `runExchange` (the shared RFC 3315 §14 retransmission loop, driving
  `InformationRequest` and every `doExchange`-based function) and `validateServerMessage` (RFC 3315's
  general validation rule: an Advertise/Reply must carry `OPTION_SERVERID`, echoed `OPTION_CLIENTID` if sent
  must match), plus the exported stateful exchanges `Solicit`/`Request`/`Renew`/`Rebind`/`Release` — all
  IA-type-agnostic (they take/return a plain `Options`/`*Message`; IA_PD-specific option decoding is
  `pkg/prefixdelegation`'s job, not this package's).
- **`pkg/aftrdiscovery/`** — RFC 6334-specific logic on top of `pkg/dhcpv6`: `dnsname.go` decodes
  `OPTION_AFTR_NAME`'s RFC 1035 wire-format name (compression pointers are invalid here per RFC 3315 §8 and
  rejected, not followed), `resolve.go` resolves it to an address via a `net.Resolver` dialed against the
  DNS servers from the same DHCPv6 Reply (`OPTION_DNS_SERVERS`), `discover.go`'s `Discover()` orchestrates
  both and returns the resolved address plus RFC 4242's refresh interval (reported, not acted on —
  periodic re-discovery is a `cmd/minuteman`-level policy decision, not yet implemented). When the Reply
  carries no `OPTION_AFTR_NAME`, `Discover` returns the sentinel `ErrNoAFTRName` *together with* a partial
  `Result` (DNS servers + refresh interval only — the one both-non-nil case, documented on the sentinel) so
  callers can feed what the Reply did carry into another discovery mechanism; `cmd/minuteman` feeds it into
  `pkg/hb46pp`.
- **`pkg/hb46pp/`** — client for HB46PP, the JAIPA-standardized "HTTP-Based IPv4 over IPv6 Provisioning
  Protocol" (v6mig-1, https://github.com/v6pc/v6mig-prov/blob/master/spec.md), the VNE-agnostic discovery
  layer many Japanese VNEs use instead of DHCPv6 AFTR-Name. `txt.go` finds the provisioning server via a
  TXT lookup on the well-known `4over6.info` (parsing `v=v6mig-1 url=... t=a|b`; the answer is VNE-specific,
  which is why lookups must go through the WAN-learned resolvers, and NXDOMAIN/NODATA/unparseable gets the
  distinct sentinel `ErrNotProvisioned` — "this VNE doesn't do HB46PP" vs. a transient failure). `t=a|b` is
  enforced as a scheme constraint (t=a ⇒ http, t=b ⇒ https with normal verification) — there is deliberately
  no skip-TLS-verify mode. `request.go` builds/validates the query parameters (vendorid/product/version/
  capability/token, each with the spec's format rules, emitted in the spec's example order rather than
  `url.Values`' alphabetical order). `response.go` decodes the JSON body: `dslite.aftr` gets a typed struct;
  the other technologies' parameter objects (`map_e`/`map_t`/`lw4o6`/`464xlat`/`ipip`) are preserved as
  `json.RawMessage` for whichever gets implemented next. `transport.go` builds the IPv6-only HTTP client
  (the spec requires IPv6-only access: hostnames resolve via AAAA only, dials are `tcp6` only) and the
  resolver-dialed-against-specific-servers helper (mirrors `pkg/aftrdiscovery`'s unexported `dialServers`).
  `discover.go`'s `Discover()` runs the whole chain single-shot — TXT → GET (redirects, including the
  spec's 307 rule, follow `http.Client`'s default policy) → decode → resolve `dslite.aftr` when present
  (a missing dslite object is *not* a Discover error, since callers may request several capabilities) —
  and `retry.go`'s `RetryDelay(err)` maps a failure to the spec's jittered backoff window (1–3h for
  `ErrNotProvisioned`, 1–10min for transient DNS, 10–30min for HTTP/JSON) so the retry *policy* stays with
  the caller, matching `aftrdiscovery`'s reported-not-acted-on stance.
- **`pkg/prefixdelegation/`** — RFC 3633-specific logic on top of `pkg/dhcpv6`, mirroring
  `pkg/aftrdiscovery`'s shape: `options.go` decodes/encodes `OPTION_IA_PD` and its nested `IAPREFIX`/
  `STATUS_CODE` suboptions (via `dhcpv6.ParseSubOptions`, since IA_PD's suboption TLV format is
  byte-for-byte identical to top-level DHCPv6 options) into `IAPD`/`IAPrefix`/`StatusCode`. `lease.go`'s
  `Lease` holds the delegating server's DUID plus the delegated prefixes and T1/T2; `clientIAID` is a fixed
  (not random or per-run-derived) constant so the server has the best chance of handing back the same
  prefix across a minuteman restart, avoiding LAN renumbering — same rationale as `duid.go`'s stable
  DUID-LL. `acquire.go`'s `Acquire()` drives the full Solicit→Advertise→Request→Reply exchange (blocks,
  retrying, until it succeeds or ctx is cancelled — same rationale as `aftrdiscovery.Discover`).
  `maintain.go`'s `Maintain()` is the part `aftrdiscovery` deliberately leaves as future work for its own
  refresh interval: a lease that's never renewed actually expires and breaks LAN connectivity, so this
  drives RFC 3315's full renewal ladder (Renew at T1 → Rebind at T2 on failure → fresh `Acquire` on failure)
  indefinitely, calling back into the caller on every change, and sends a best-effort `Release` on shutdown.
- **`pkg/routeradvert/`** — RFC 4861 (Neighbor Discovery) logic covering only what a CPE needs: sending
  Router Advertisements on the LAN side, plus (`solicit.go`) sending Router Solicitations upstream on the
  WAN side — `SolicitRouters` transmits §6.3.7's host cadence (3 RSes, 4s apart) and lets the kernel
  process the RAs that come back; it exists to promptly restore the default route the forwarding-enable
  purge removes (see `pkg/datapath` above). Not the full NDP message set. `message.go`/`options.go`
  are the wire codec (manual byte-slice framing, matching `pkg/dhcpv6`'s style) for the RA fixed header and
  the two NDP options this package builds, `PrefixInformation` (§4.6.2) and `SourceLinkLayerAddress`
  (§4.6.1); Marshal-only, since this package never needs to decode an RA or an RS's body, only detect that
  an RS arrived (`isRouterSolicitation`). `transport.go`'s `Conn` hand-rolls a raw `AF_INET6`/`SOCK_RAW`/
  `IPPROTO_ICMPV6` socket (`golang.org/x/sys/unix`, no `golang.org/x/net/icmp` — same no-external-library
  philosophy as `internal/lanprefix`'s netlink code), joining the All-Routers multicast group so it
  actually receives Router Solicitations, setting both hop limits to 255 (RFC 4861 §6.1.2's anti-spoofing
  requirement), and installing an `ICMP6_FILTER` so its read loop only wakes for Router Solicitation
  traffic (`ICMP6_FILTER`'s sockopt-name constant isn't exported by `x/sys/unix` on Linux, so it's vendored
  locally, the same rationale as `bpf/uapi/linux/*.h`). `advertise.go`'s `Serve(ctx, iface, cfg)` is the
  actual RFC 4861 §6.2/§10 timing — a fast initial burst of RAs, settling into a jittered periodic
  cadence, plus rate-limited replies to inbound Router Solicitations — ending with a best-effort final
  `RouterLifetime=0` RA when `ctx` is cancelled (§6.2.5's graceful-shutdown signal), mirroring
  `prefixdelegation.Maintain`'s blocks-until-cancelled shape. A send failing with `EADDRNOTAVAIL` is
  retried on DAD's ~1s timescale rather than treated as fatal: it means the interface's link-local source
  is still tentative, which genuinely happens in minuteman's startup sequence (XDP attach can bounce the
  link, and the LAN address assignment lands immediately before `Serve` starts) and used to kill the RA
  worker for good, leaving LAN clients with no SLAAC.
- **`cmd/minuteman/main.go`** — thin CLI entrypoint. Flags: `-wan`, `-b4`, `-aftr` (optional — see below),
  repeatable `-lan iface=gatewayIP[,mtu]`, `-wan-dst-mac` (fallback only), `-stats-interval`, `-dhcpv6-pd`
  (opt-in prefix delegation). Flag-value parsing (`LANSpec`/`LANSpecList`, MAC parsing) lives in
  `internal/cliconfig`, not in `main.go` itself. `resolveAFTR()` returns `-aftr` parsed directly if given,
  otherwise blocks on `pkg/aftrdiscovery.Discover` using the same lifecycle context as `SIGINT`/`SIGTERM`
  handling (no artificial timeout — indefinite RFC 3315 retry is correct here, since there's no working
  DS-Lite path without an AFTR anyway). On `aftrdiscovery.ErrNoAFTRName` it falls back to
  `hb46pp.Discover` (capability `dslite` only, DNS servers from the partial DHCPv6 result; the client
  identity constants use the documentation OUI `acde48` since minuteman has no IEEE OUI), looping the whole
  DHCPv6→HB46PP chain with `hb46pp.RetryDelay`-paced sleeps on HB46PP failure — same
  block-until-success-or-ctx-cancel stance, but at the spec's backoff cadence so a real VNE's provisioning
  server isn't hammered. When `-dhcpv6-pd` is set, `runPrefixDelegation()` similarly blocks
  on `pkg/prefixdelegation.Acquire`, then applies the initial LAN assignment via
  `internal/lanprefix.Reconcile` synchronously (before the datapath is considered "up"), syncs an
  `internal/lanprefix.RAManager` against the result (starting one `pkg/routeradvert.Serve` goroutine per
  `-lan` interface, also tracked on the same `sync.WaitGroup`), then starts `pkg/prefixdelegation.Maintain`
  in a background goroutine (tracked on that `sync.WaitGroup` that `run()` waits on before returning, so a
  shutdown's best-effort `Release` and every RA worker's best-effort final advertisement all get a chance
  to finish) with that same `Reconcile`+`RAManager.Sync` pair as its `onLeaseChange` callback. Otherwise
  `main.go` just orchestrates
  `pkg/datapath.Loader` calls (`Load`/`AttachWAN`/`SetB4Config`/`AttachLAN`+`SetLANConfig` per `-lan`/`Stats`
  on a timer) — it never touches `cilium/ebpf` or BPF map layouts directly.
- **`internal/cliconfig`** — parses `minuteman`'s flag values (`LANSpec`, `ParseLANSpec`, `LANSpecList`
  implementing `flag.Value`, `ParseMAC`) into typed values for `main.go` to hand to `pkg/datapath`. Thin
  CLI-flag glue only, not a home for protocol logic (that's `pkg/dhcpv6`/`pkg/aftrdiscovery`/`pkg/hb46pp`/
  `pkg/prefixdelegation`).
- **`internal/lanprefix`** — the DHCPv6-PD *policy* layer: what to do with a delegated prefix, as opposed to
  the protocol client itself (`pkg/prefixdelegation`). `carve.go`'s `SubnetFor(delegated, index)`/
  `AssignedAddress(subnet)` are pure functions (bit manipulation on a `netip.Prefix`'s first 8 bytes, no
  I/O) that carve one `/64` per `-lan` interface's position in the flag list out of the delegated prefix and
  pick its `::1` address. `netlinkmsg.go` builds/parses raw `RTM_NEWADDR`/`RTM_DELADDR` netlink request and
  `NLMSG_ERROR` ack bytes using `golang.org/x/sys/unix`'s existing wire-layout structs (`NlMsghdr`,
  `IfAddrmsg`, `RtAttr`) — no netlink/rtnetlink *library* dependency, matching this project's no-sidecar,
  no-external-process ethos (`pkg/datapath/sysctl.go` avoids `sysctl`/`ip` exec the same way). `netlink.go`
  is the actual `AF_NETLINK`/`NETLINK_ROUTE` socket I/O; `NLM_F_REPLACE` on `addAddr` makes re-asserting an
  unchanged address idempotent, matching `pkg/datapath`'s "safe to call repeatedly" configuration setters.
  `reconcile.go`'s `Reconcile()` ties it together per LAN interface, removing a stale address first if a
  renewal changed which `/64` it should have, and also returns each interface's `ValidLifetime`/
  `PreferredLifetime` (taken from the delegated prefix, not derived) on the resulting `Assignment` for
  `ra.go` to consume. `ra.go`'s `RAManager` drives one `pkg/routeradvert.Serve` goroutine per LAN interface
  from those `Assignment`s: `Sync()` always restarts a LAN interface's worker on every call (not just when
  its `Subnet` changes), since a Renew resets the lifetimes even when the subnet itself doesn't change and
  a long-running `Serve` goroutine has no other way to pick that up — restarting is cheap, unlike
  `Reconcile`'s netlink unchanged-skip optimization, which exists to avoid transient route churn that
  restarting an RA sender doesn't have an equivalent of.

When implementing new functionality, follow this split: per-packet fast-path logic goes in
`bpf/datapath.bpf.c`; anything that needs `cilium/ebpf` or knows about BPF map layouts goes in
`pkg/datapath`; generic protocol/wire-format code goes in its own `pkg/` package the way
`pkg/dhcpv6`/`pkg/aftrdiscovery`/`pkg/hb46pp`/`pkg/prefixdelegation`/`pkg/routeradvert` do; CLI-specific
glue and policy
decisions belong in `internal/` or `cmd/` (e.g. `internal/lanprefix`'s delegated-prefix-to-LAN-address and
delegated-prefix-to-RA policy), calling into the `pkg/` packages rather than duplicating their logic.

## Design reference: gregw's XDP datapath

[shun159/gregw](https://github.com/shun159/gregw) (`bpf/datapath.bpf.c` + `bpf/datapath_helpers.h`) is a sister
project by the same author — a GRE (IPv4-in-IPv4) tunneling CPE datapath — and is the structural template
minuteman's DS-Lite datapath was built from (config-via-maps, `PERCPU_ARRAY` stats, FIB-based next-hop
resolution with wrong-interface checks, in-datapath PMTUD/ICMP synthesis, `adjust_head`/`adjust_tail` with
bounds re-validation, CPU fanout via `cpumap`, shared helpers in a separate header). The main structural
difference is the tunnel encapsulation itself: gregw wraps IPv4-in-IPv4 over GRE between two fixed peers,
whereas minuteman wraps IPv4-in-IPv6 directly (`nexthdr = IPPROTO_IPIP`, no GRE header) between the B4 and the
AFTR. When extending the datapath (e.g. sending Router Advertisements out DHCPv6-PD-assigned LAN prefixes,
multiple AFTR candidates, or hairpinning), check gregw's implementation first for an equivalent pattern
before designing one from scratch.
