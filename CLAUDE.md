# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project purpose

Minuteman is a high-performance CPE (Customer Premises Equipment) gateway for home use, built on XDP/eBPF.
The goal is a practical, production-usable system covering the functionality a home gateway needs — including
DHCPv6 Prefix Delegation (PD) and AFTR (DS-Lite) resolution — on top of an XDP-based fast-path datapath.

## Current state

Feature-complete as a DS-Lite (RFC 6333) B4 element, plus the pieces a real home CPE also needs. Each
item below is independently toggled unless noted, and its mechanics are covered in depth in Architecture
further down — this is just the index of what exists and which flag turns it on.

- **DS-Lite B4 datapath** (always on) — attaches/runs against real interfaces; XDP programs load, pass
  the kernel verifier, and have processed live traffic on veth pairs.
- **AFTR discovery** (automatic unless `-aftr` is given) — an in-process, stdlib-only DHCPv6 client
  (RFC 3736 + RFC 6334 `OPTION_AFTR_NAME`) with an HB46PP (JAIPA v6mig-1) fallback when the Reply carries
  no AFTR-Name, so minuteman needs no per-VNE configuration and spawns no external DHCP/DNS daemon.
- **DHCPv6 Prefix Delegation** (`-dhcpv6-pd`, RFC 3633) — acquires and maintains a delegated prefix,
  carves one `/64` per `-lan` interface from it, and RAs it out (RFC 4861) for LAN SLAAC.
- **NDProxy** (`-ndproxy`, RFC 4389) — the alternative WAN model some ISPs use instead of PD (one shared
  WAN `/64`, extended onto the LAN): actively verifies a LAN target before proxying NS/NA for it, rather
  than passively snooping. Mutually exclusive with `-dhcpv6-pd` (alternative WAN provisioning models).
- **DNS proxy** (`-dns-proxy`, RFC 6333's B4 SHOULD) — opaque byte relay to upstream DNS server(s),
  structurally bypassing the softwire (an ordinary native-IPv6 socket from the CPE's own process).
- **DHCPv4 server** (`-dhcpv4`, RFC 2131/2132) — hands LAN clients the private IPv4 the softwire carries,
  with a DS-Lite-adjusted MTU (option 26). Needed a datapath change (see `xdp_dslite_encap` below) so
  broadcast DISCOVER/REQUEST traffic isn't wrapped into the softwire before reaching the server.
- **Native-IPv6 forwarding fastpath** (always on) — transit IPv6 that used to fall to the kernel slow
  path (`XDP_PASS`) is now routed directly in XDP, with in-datapath ICMPv6 Packet Too Big and an optional
  software-RSS cpumap stage (`-ipv6-sw-rss`, off by default — for NICs without capable hardware RSS).

All of the above has been verified end-to-end against the netns rig (see Testing below).

`internal/` holds `cliconfig` (CLI flag parsing), `lanprefix` (DHCPv6-PD LAN policy, including RA
serving), and `wanextend` (NDProxy LAN policy, including RA serving and host-route management);
`pkg/dhcpv6`/`pkg/aftrdiscovery`/`pkg/hb46pp`/`pkg/prefixdelegation`/`pkg/routeradvert`/`pkg/ndproxy`/
`pkg/netlink`/`pkg/dnsproxy`/`pkg/dhcpv4` are the reusable protocol packages.

Not yet implemented:
- The migration technologies other than DS-Lite that an HB46PP response can describe (`map_e`/`map_t`/
  `lw4o6`/`464xlat`/`ipip`). `pkg/hb46pp` already decodes the response's `order`-ranked technology list
  and preserves those technologies' parameter objects raw (`json.RawMessage` on `hb46pp.Provisioning`),
  so implementing one means adding its typed parameter struct there, its datapath, and extending
  `cmd/minuteman`'s policy beyond the current dslite-only capability request.
- The WAN/link-change half of AFTR re-discovery. What *is* implemented: `cmd/minuteman`'s
  `runAFTRRediscovery` re-runs discovery on the refresh interval each result reports (echoing the HB46PP
  `Token`, with DHCPv6 exchanges on the WAN serialized against DHCPv6-PD maintenance by `pkg/dhcpv6`'s
  per-interface lock), and a changed AFTR is applied by `migrateAFTR` *without breaking the flows that
  predate it* — the datapath primes a flow-affinity table on the old AFTR, cuts over, then keeps those
  flows pinned to the old AFTR until they fall idle (see `pkg/datapath/migration.go` and the control
  word in `bpf/datapath.bpf.c`). Still missing: the WAN/link-change re-discovery triggers (RFC 9915),
  which are blocked on dynamic B4 — today `-b4` is a static flag, so a changed WAN address has no live
  value to switch to (and can't be drained at all: the AFTR's NAT state is keyed to the B4 address, so
  it dies with it). See `docs/rfc-compliance-backlog.md`'s dynamic-B4 entry.
- A handful of RFC 7084/6333 compliance gaps (softwire fragmentation, RFC 6333 §5.3's MUST, is the
  highest-impact one remaining). See `docs/rfc-compliance-backlog.md` for the full, priority-ordered
  list with the specific code each gap points at.

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

`test/netns/` builds a 5-namespace RFC 6333 topology (LAN client → CPE running minuteman as the B4 → IPv6
access network → AFTR simulator → simulated public IPv4 internet) to exercise the datapath end-to-end
without physical hardware:

```sh
sudo ./test/netns/setup.sh       # builds the namespaces/veths/routing/NAT
sudo ./test/netns/run-cpe.sh     # runs bin/minuteman as the B4 inside mm-cpe (discovers the AFTR live)
sudo ./test/netns/smoketest.sh   # starts minuteman itself + pings/curls end-to-end
sudo ./test/netns/teardown.sh    # tears everything down (always safe to re-run)
```

Six independent env-var toggles select what `setup.sh` builds and what `smoketest.sh` asserts —
`MM_AFTR_DISCOVERY` (`dhcpv6`/`hb46pp`), `MM_WAN_MODEL` (`dhcpv6-pd`/`ndproxy`), `MM_DNS_PROXY`,
`MM_DHCPV4`, `MM_DUALSTACK`, `MM_IPV6_SW_RSS` — plus the full list of verified-passing combinations. See
**`test/netns/README.md`** for all of that detail; it's a rig-operation runbook, not something most tasks
need loaded up front.

`run-cpe.sh` and `smoketest.sh` deliberately omit `-aftr` so minuteman discovers it live against the rig —
pass `-aftr <addr>` as an extra argument to either script to override with a static address instead.

Two things that will break the rig if changed casually:
- `mm-cpe` needs both `net.ipv4.ip_forward=1` and `net.ipv6.conf.all.forwarding=1`, or `bpf_fib_lookup()`
  returns `BPF_FIB_LKUP_RET_FWD_DISABLED` for every packet — but this is applied by
  `pkg/datapath.Loader.AttachWAN` itself (see Architecture below), not by `setup.sh`, so it happens
  whenever minuteman runs, not just in this rig.
- mm-isp's dnsmasq must be started, and mm-cpe's WAN link brought up, in that order — Linux only retries
  Router Solicitation a few times right after an interface comes up, so a late RA server means the CPE
  never gets a default route; `setup.sh` sequences this deliberately, don't reorder it.

The AFTR's decap step uses a kernel `ip6tnl` device, which needs the `ip6_tunnel` module; `setup.sh`
checks for it up front (with an Arch-specific diagnostic for the common case where a kernel upgrade has
orphaned the running kernel's module directory — reboot to fix that).

## Code style

- C (eBPF) formatting is enforced via `.clang-format`: 4-space indent, right-aligned pointers, 90-column limit,
  custom brace wrapping (opening brace on its own line only after function definitions). Run `clang-format` on
  `bpf/*.bpf.c`/`bpf/*.h` before committing.
- Go module path is `github.com/shun159/miniteman` (note: `miniteman`, not `minuteman` — a pre-existing typo in
  `go.mod`; match it exactly in imports), building on Go 1.26.2.

## Architecture

- **`bpf/datapath.bpf.c`** — the DS-Lite XDP datapath. Two independently attachable programs:
  - `xdp_dslite_encap` (`SEC("xdp")`, attach to LAN interfaces): parses inbound IPv4, bypasses DS-Lite for
    LAN-local traffic (`is_local_gateway_dst` / `is_local_lan_route`, via `bpf_fib_lookup`) and for
    non-unicast IPv4 destinations (`is_non_unicast_dst`: limited broadcast + multicast, which a
    point-to-point softwire must never carry — this is also what lets a LAN client's limited-broadcast DHCP
    DISCOVER/REQUEST reach minuteman's own `-dhcpv4` server, which listens via an AF_PACKET socket
    downstream of XDP), checks WAN path MTU
    accounting for the 40-byte IPv6 encap overhead (`TUNNEL_L3_OVERHEAD`), replies with a plain ICMPv4
    Fragmentation-Needed via `XDP_TX` when needed (`send_plain_icmp_frag_needed` — untunneled, since the LAN
    sender is directly reachable on the ingress interface), then wraps the packet in an outer
    Ethernet+IPv6(nexthdr=`IPPROTO_IPIP`) header and redirects it out the WAN ifindex via the `tx_ports`
    `DEVMAP_HASH`. Native IPv6 arriving here (a LAN client's IPv6 transit traffic) is *not* IPv4, so instead
    of being encapsulated it takes the native-IPv6 forwarding fastpath (`handle_ipv6_forward`, see below).
  - `xdp_dslite_decap` (`SEC("xdp")`, attach to the WAN interface) / `xdp_dslite_decap_cpu` (`SEC("xdp/cpumap")`
    second-stage variant): validates the outer IPv6 header matches the configured AFTR/B4 pair
    (`is_expected_dslite_peer`), optionally fans decap work out across CPUs first
    (`maybe_redirect_to_cpu` + the `cpu_map`/`fanout_*` maps, gated by `fanout_config.enabled`), strips the
    IPv6 header, resolves the LAN egress interface via `bpf_fib_lookup`, and — if the egress path MTU is too
    small — replies with an ICMPv4 Fragmentation-Needed re-encapsulated back through the softwire
    (`send_dslite_icmp_frag_needed`, since the original IPv4 sender is only reachable via the AFTR). Native
    (non-softwire) IPv6 arriving on the WAN — the `outer_iph->nexthdr != IPPROTO_IPIP` case, previously
    `XDP_PASS`ed to the kernel — takes the same native-IPv6 forwarding fastpath instead.
  - `handle_ipv6_forward` — the native-IPv6 forwarding fastpath, a plain IPv6 router step shared by the
    encap (LAN-ingress), decap (WAN-ingress) and `xdp_ipv6_fwd_cpu` (software-RSS) programs. It does in XDP
    what the kernel slow path would otherwise do for every transit IPv6 packet: `bpf_fib_lookup(AF_INET6)`,
    rewrite L2 from the resolved `dmac`/`smac`, `decrease_ipv6_hoplimit`, and `bpf_redirect_map` out the
    egress ifindex (`tx_ports`). It is deliberately conservative — anything that isn't cleanly forwardable
    transit is handed back to the kernel via `XDP_PASS`, so NDP/RA/RS/NS/NA, DHCPv6, MLD and local delivery
    all keep working unchanged: multicast (`ff00::/8`) and link-local (`fe80::/10`) destinations are rejected
    up front (`ipv6_is_forwardable`); a FIB result other than `SUCCESS` is passed to the kernel (`NOT_FWDED`
    = destined to one of the CPE's own addresses → local delivery, `NO_NEIGH` = kernel resolves ND then
    later packets fast-path, `FWD_DISABLED`, unreachable/blackhole/prohibit); and an egress that is the
    ingress interface, or not one of the managed WAN/LAN interfaces, is passed too. Unlike the plan's first
    cut, PMTUD is served *here*, not deferred to the kernel: on `BPF_FIB_LKUP_RET_FRAG_NEEDED` it originates
    ICMPv6 Packet Too Big itself (`send_icmpv6_pkt_too_big` → `write_icmpv6_pkt_too_big`, a plain untunneled
    `XDP_TX` reply back out the ingress interface — IPv6 is never softwire-tunneled, so the sender is always
    directly reachable, the IPv6 analogue of the encap path's `send_plain_icmp_frag_needed`), sourced from
    the CPE's own `b4_addr` (falling back to `XDP_PASS` if that's unset). Native IPv6 forwarding is always
    on (no flag), the same posture as DS-Lite's inner-IPv4 forwarding. Known simplifications: VLAN-tagged
    IPv6 and packets whose transport is behind IPv6 extension headers stay on the kernel path; the PtB source
    is the single `b4_addr` rather than a per-ingress-interface address.
  - `xdp_ipv6_fwd_cpu` (`SEC("xdp/cpumap")`) + `maybe_redirect_ipv6_to_cpu` — an *optional* software-RSS
    (CPU-fanout) stage for the native-IPv6 fastpath, off by default. When `ipv6_rss_config.enabled`, the
    encap/decap entry programs hash the flow (`inner_ip6_hash`) and `bpf_redirect_map` the packet to another
    CPU's `cpu_map_v6` queue, where `xdp_ipv6_fwd_cpu` re-parses and runs `handle_ipv6_forward` (ingress
    ifindex is preserved across the redirect, so the FIB/egress checks behave identically). It uses its own
    dedicated maps (`ipv6_rss_config_map`/`ipv6_rss_cpus`/`cpu_map_v6`) rather than the DS-Lite
    `fanout_config`/`fanout_cpus`/`cpu_map` — the DS-Lite CPU-fanout scaffold is dormant (never enabled from
    Go), and IPv6 software RSS must be switchable without waking it. It's for NICs whose hardware RSS can't
    spread flows across CPUs; on hardware-RSS-capable NICs (e.g. mlx4) it's redundant and left off. Enabled
    via `-ipv6-sw-rss` → `Loader.EnableIPv6SoftwareRSS`.
  - Config is held in BPF maps, not hardcoded: `b4_config_map` (single-entry `ARRAY`: B4/AFTR IPv6 addresses,
    fallback WAN MACs, WAN ifindex) and `lan_configs` (`HASH` keyed by LAN ifindex: gateway IPv4, inner MTU).
    The optional IPv6 software-RSS stage adds `ipv6_rss_config_map`/`ipv6_rss_cpus`/`cpu_map_v6` (separate
    from the dormant DS-Lite `fanout_*`/`cpu_map`). Per-path counters live in the `stats` `PERCPU_ARRAY`
    (see `enum stat_id`; the field/index order in `pkg/datapath/stats.go`'s `statID` and the `Stats` struct
    must be kept in sync with it by hand — new counters are appended before `STAT_MAX`).
  - Every ICMP error the datapath originates (`send_plain_icmp_frag_needed`,
    `send_dslite_icmp_frag_needed`, `send_icmpv6_pkt_too_big`) is gated by `icmp_error_allowed()`, a
    per-CPU token bucket (`icmp_error_rate` `PERCPU_ARRAY`, 100/s sustained + 20 burst per CPU) — RFC 4443
    §2.4(f) makes rate-limiting originated ICMPv6 errors a MUST, and these `XDP_TX` replies bypass the
    kernel's own `icmp_ratelimit` sysctls entirely. When the bucket is empty the offending packet is
    dropped without an error (mirroring the kernel's own behavior), counted in `STAT_ICMP_RATE_LIMITED`.
  - **`bpf/datapath_helpers.h`** — shared low-level helpers (checksum fold/compute, IPv4 TTL decrement with
    incremental checksum update, IPv6 hop-limit decrement (`decrease_ipv6_hoplimit` — no checksum, so
    trivial), L2(+VLAN)/IPv4/IPv6 header parsing with bounds checks, IPv6 address comparison and
    unspecified/forwardable classification (`ipv6_addr_equal`/`ipv6_addr_is_unspecified`/`ipv6_is_forwardable`),
    IPv6 flow hashing (`inner_ip6_hash`), and ICMP error construction: ICMPv4 Fragmentation-Needed in both
    plain and DS-Lite-tunneled form, plus ICMPv6 Packet Too Big (`write_icmpv6_pkt_too_big`, whose
    `icmpv6_checksum` covers the IPv6 pseudo-header, unlike ICMPv4's).
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
  - `ipv6_rss.go` — `EnableIPv6SoftwareRSS([]uint32)` turns on the native-IPv6 software-RSS cpumap stage
    across the given CPU ids: it populates `cpu_map_v6` with `bpfBpfCpumapVal{Qsize, prog: XdpIpv6FwdCpu.FD()}`
    per CPU, fills `ipv6_rss_cpus` (slot → cpu), and sets `ipv6_rss_config{Enabled, CpuCount}`. Off unless
    called (`-ipv6-sw-rss`). `cilium/ebpf` v0.21 has no high-level CPUMAP-with-program value helper, so the
    raw `bpf_cpumap_val` struct bpf2go generated (`bpfBpfCpumapVal`) is `Put` directly.
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
  enforced as a scheme constraint per spec §3.2's four connection methods: t=b requires https with normal
  certificate validation; t=a permits *either* http or https-without-verification (`ServerInfo.ValidateCert`
  carries which), since the spec's only directional rule is that a plain-http URL must be paired with t=a,
  not the converse. `request.go` builds/validates the query parameters (vendorid/product/version/
  capability/token, each with the spec's format rules, emitted in the spec's example order rather than
  `url.Values`' alphabetical order). `response.go` decodes the JSON body: `dslite.aftr` gets a typed struct;
  the other technologies' parameter objects (`map_e`/`map_t`/`lw4o6`/`464xlat`/`ipip`) are preserved as
  `json.RawMessage` for whichever gets implemented next; `order: []` (spec-valid — "no method available for
  this client") is distinguished from the field being absent (spec-invalid) via Go's own nil-vs-empty-slice
  `json.Unmarshal` behavior, no wire-type indirection needed. `fetchProvisioning` follows *only* the spec's
  307-to-another-server redirect (`newHTTPClient`'s `CheckRedirect` disables `http.Client`'s own broader
  default policy, which also treats 301/302/303/308 as redirects — a meaning this protocol doesn't define —
  so `fetchProvisioning`'s loop, capped at `maxRedirects`, is the only redirect-following that happens), and
  rejects a redirect target that isn't https when the original record was t=b. Response bodies over
  `maxResponseBytes` are rejected outright (not silently truncated-and-decoded), and any non-whitespace data
  left after the JSON object is also rejected. `transport.go` builds the IPv6-only HTTP client (the spec
  requires IPv6-only access: hostnames resolve via AAAA only, dials are `tcp6` only) and the
  resolver-dialed-against-specific-servers helper (mirrors `pkg/aftrdiscovery`'s unexported `dialServers`).
  `discover.go`'s `Discover()` runs the whole chain single-shot — TXT → GET → decode → resolve `dslite.aftr`
  when present (a missing dslite object is *not* a Discover error, since callers may request several
  capabilities) — and `retry.go`'s `RetryDelay(err)` maps a failure to the spec's jittered backoff window
  (1–3h for `ErrNotProvisioned`, 1–10min for transient DNS, 10–30min for HTTP/JSON) so the retry *policy*
  stays with the caller, matching `aftrdiscovery`'s reported-not-acted-on stance.
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
  philosophy as `pkg/netlink`), joining the All-Routers multicast group so it
  actually receives Router Solicitations, setting both hop limits to 255 (RFC 4861 §6.1.2's anti-spoofing
  requirement), and installing an `ICMP6_FILTER` so its read loop only wakes for Router Solicitation
  traffic (`ICMP6_FILTER`'s sockopt-name constant isn't exported by `x/sys/unix` on Linux, so it's vendored
  locally, the same rationale as `bpf/uapi/linux/*.h`). `advertise.go`'s `Serve(ctx, iface, cfg)` is the
  actual RFC 4861 §6.2/§10 timing — a fast initial burst of RAs, settling into a jittered periodic
  cadence, plus rate-limited replies to inbound Router Solicitations — ending with a best-effort final
  `RouterLifetime=0` RA when `ctx` is cancelled (§6.2.5's graceful-shutdown signal), mirroring
  `prefixdelegation.Maintain`'s blocks-until-cancelled shape. A send failing with `EADDRNOTAVAIL` is
  retried on DAD's ~1s timescale (`tentativeRetryInterval`) rather than treated as fatal: it means the
  interface's link-local source is still tentative, which genuinely happens in minuteman's startup
  sequence (XDP attach can bounce the link, and the LAN address assignment lands immediately before
  `Serve` starts) and used to kill the RA worker for good, leaving LAN clients with no SLAAC.
  `SolicitRouters` (`solicit.go`) shares this same retry (`sendRetryingTentative`) for exactly the same
  reason — it's fired right after `AttachWAN`'s own forwarding-flip, which can itself still have the WAN
  link's address tentative. `Config.OnLink` sets the Prefix Information Option's L flag: true for
  `internal/lanprefix`'s DHCPv6-PD model (the advertised `/64` really is distinct and on-link for that LAN
  interface), false for `internal/wanextend`'s NDProxy model (the `/64` is shared with the WAN, so LAN
  clients must route everything — not just off-prefix traffic — through the CPE, which is what makes
  WAN-side NDProxy's answers the only way reachability happens rather than needing LAN-side proxying too).
- **`pkg/ndproxy/`** — RFC 4389 (Neighbor Discovery Proxy) logic: answering Neighbor Solicitations on a WAN
  link on behalf of LAN hosts, for the ISP model where the WAN's own `/64` is extended onto the LAN instead
  of a distinct prefix being delegated (see `internal/wanextend`). Rather than passively snooping LAN
  NS/NA traffic to learn which addresses exist (which would need `ALLMULTI` on every LAN interface and
  trust stale state), it actively verifies: a WAN-side NS for an unknown target triggers an NS probe on the
  LAN side, and only a real NA reply makes the proxy answer upstream — the same shape ndppd's "auto" mode
  uses. `message.go` is the NS/NA wire codec (marshal-only for the proxy's own probes/replies, parse-only
  for `Target Address` extraction — options are never decoded, since the proxy never needs a peer's
  link-layer address). `conn.go` is the LAN-side raw `IPPROTO_ICMPV6` socket (filtered to one message type
  via `ICMP6_FILTER`, vendored the same way `pkg/routeradvert` vendors it), sending probes and receiving
  replies; `packet.go` is the WAN-side receiver, which can't use a raw ICMPv6 socket at all — a Neighbor
  Solicitation is sent to the target's Solicited-Node multicast group, a different group per target
  address, and the kernel drops multicast for groups never joined before a raw socket ever sees it — so it
  uses a cooked `AF_PACKET` socket instead (matching ndppd's own approach) with `ALLMULTI` plus a
  classic-BPF filter (`nsFilter`) so only Neighbor Solicitations ever reach userspace. `state.go`'s
  `proxyState` is the pure decision logic (no I/O, an explicit `now time.Time` on every method instead of
  reading the clock, so it's tested without real sockets or timers): which targets are mid-probe, which are
  confirmed active (with a CPE-local `activeTTL`, not RFC-mandated, bounding how long a confirmation is
  trusted before re-probing), and what `sweep()`'s periodic tick should retransmit, give up on, or expire.
  `serve.go`'s `Serve(ctx, wanIface, lanIfaces, Config)` wires `conn`/`packetConn`/`proxyState` into a
  running proxy — one `select` loop over the WAN NS channel, a fanned-in LAN NA channel (tagged with
  source interface, since `conn` itself doesn't know its own name), and the sweep ticker. `Config.OnActive`/
  `OnInactive` fire on activation/expiry so a caller can install/remove a host route (`internal/wanextend`
  does); every channel send in this package is non-blocking/drop-on-full (`select`+`default`, matching
  `packetConn.readSolicitations`'s original rationale: NDP retransmits, so a dropped message only delays
  resolution, and a blocking send here would otherwise leak a goroutine past `Serve` returning). Deliberate
  non-goals vs. full RFC 4389 (documented on the package itself): no cross-link DAD proxying, no
  RA/Redirect proxying (the caller re-advertises the WAN prefix on the LAN with On-Link cleared instead),
  no proxy-loop detection.
- **`pkg/netlink/`** — minimal, hand-rolled `AF_NETLINK`/`NETLINK_ROUTE` client (`golang.org/x/sys/unix`,
  no netlink library, matching `pkg/datapath/sysctl.go`'s `sysctl`-exec-avoidance the same way): the only
  package that builds/parses netlink wire messages, used by both `internal/lanprefix` (address assignment)
  and `internal/wanextend` (WAN-prefix discovery, host routes) — split out from `internal/lanprefix`'s
  original private implementation once `internal/wanextend` needed the same mechanism. `message.go` builds
  `RTM_NEWADDR`/`RTM_DELADDR`/`RTM_GETADDR`/`RTM_NEWROUTE`/`RTM_DELROUTE` requests and parses responses —
  `walkMessages` splits a single `Recvfrom` buffer into individual messages (a dump response packs several
  together), `parseIfAddrMsg` decodes an `RTM_NEWADDR` dump entry's `IFA_ADDRESS`/`IFA_LOCAL` attributes,
  filtering to global scope (`RT_SCOPE_UNIVERSE`) since WAN-prefix discovery has no use for the WAN's own
  link-local address. `socket.go`'s `Socket` is the actual send/receive I/O: `AddAddr`/`DelAddr` (`NLM_F_
  REPLACE` makes `AddAddr` idempotent), `Addrs` (an `RTM_GETADDR` dump, looping `Recvfrom` until
  `NLMSG_DONE`), `AddRoute`/`DelRoute` (a directly-attached route — `RTA_OIF` only, no `RTA_GATEWAY`, scope
  `RT_SCOPE_LINK` — matching `ip route add <dst> dev <iface>`; `AddRoute` is `NLM_F_REPLACE`-idempotent
  too).
- **`pkg/dnsproxy/`** — the DNS proxy RFC 6333 recommends a DS-Lite B4 run (the B4 SHOULD act as a DNS
  proxy for LAN clients): opaque byte-relay only, no DNS message parsing, caching, or rewriting of any
  kind, so it's simple enough to have no unit tests of its own (like `pkg/ndproxy`/`pkg/routeradvert`'s raw
  socket I/O, correctness here is exercised by `test/netns`, not `go test`). `serve.go` splits opening
  from serving the same way `pkg/dhcpv4` does (`New`/`Serve`): `Listen(Config)` opens a UDP `net.ListenUDP`
  and TCP `net.ListenTCP` socket per `Config.ListenAddrs` (port 53) *synchronously*, returning a `*Server`
  or a bind failure to the caller (so `cmd/minuteman` fails fast, and only advertises one of these
  addresses as an RDNSS DNS server once it's actually bound — see `startDNSProxy`/`routeradvert`), and the
  returned `Server`'s `Serve(ctx)` runs the forwarding loops, closing every socket on `ctx.Done()` to
  unblock `serveUDP`/`serveTCP`'s read loops — the same close-to-unblock shutdown pattern `pkg/ndproxy`'s
  `conn`/`packetConn` use. A listen address that's IPv6 link-local carries a zone (`netip.Addr.Zone()`,
  set by `routeradvert.LinkLocalAddr`), threaded into the `net.UDPAddr`/`net.TCPAddr` so the kernel binds
  it to the right interface. `udp.go`'s `serveUDP` spawns
  one goroutine per received datagram (so one slow upstream never blocks the next query), trying
  `Config.Upstreams` in order over a fresh one-shot `net.DialUDP` socket per query (deliberately not
  pooled: a dedicated socket means a response can never be confused with a different concurrent query's,
  and DNS-over-UDP is a single round trip anyway) bounded by `udpQueryTimeout`; every upstream failing just
  drops the query, relying on the client's own resolver to retry, same as if this proxy weren't in the
  path. `tcp.go`'s `relayTCP` is a full bidirectional byte-level `io.Copy` relay per accepted connection
  rather than framing individual length-prefixed DNS-over-TCP messages — RFC 7766 §6.2.1 allows pipelining
  multiple queries on one connection, which a byte relay handles for free without this package ever
  needing to parse a message boundary.
- **`pkg/dhcpv4/`** — the LAN-side DHCPv4 *server* (RFC 2131/2132) minuteman runs behind `-dhcpv4` to hand
  its LAN clients the private IPv4 the DS-Lite softwire carries. Server only, and only the directly-attached
  single-subnet-per-interface case a home CPE serves (no BOOTP relay — a `giaddr != 0` request is rejected,
  not mis-answered — no shared networks, no restart persistence: an in-memory pool). Follows the same
  pure-vs-I/O split as `pkg/ndproxy`: `message.go`/`options.go` are the BOOTP + magic-cookie + option TLV
  wire codec (`Options.Marshal` splits a value past 255 bytes across repeated option instances per RFC 3396
  rather than truncating a length byte); `lease.go`'s `Pool` is the address allocator, pure with an explicit
  `now time.Time` like `ndproxy`'s `proxyState`. The pool distinguishes an *offered* binding (held only for
  the short `offerHoldTime`, so a DISCOVER that never turns into a REQUEST — a client that chose another
  server, or a spoofed one — can't tie up an address for the full lease) from a *committed* one (`Offer`
  vs. `Commit`), quarantines a DHCPDECLINEd address only if the declining client actually held it and only
  for a bounded `declineQuarantine` (so a client can't poison the pool with addresses it was never leased),
  and exposes `Binding`/`CancelOffer` so the handler can make RFC-correct decisions. `handler.go`'s `handle`
  is the pure request→reply (or nil) decision: it distinguishes RFC 2131 §4.3.2's three DHCPREQUEST
  substates by which of server-id/requested-IP/ciaddr are set, ACKs a REQUEST only for the address this
  server actually offered or leased the client (a REQUEST from a client it has no record of — including a
  returning client's INIT-REBOOT after a restart wiped the pool — gets silence, not an ACK of a free
  address, so independent servers on one segment coexist; the client falls back to DISCOVER), validates the
  server-id on RELEASE/DECLINE, and leaves `siaddr` zero (it's the next-bootstrap-server field, not the
  server id). All three files are unit-tested with no sockets. `packet.go` is the raw AF_PACKET I/O (a DHCP
  server can't use an ordinary UDP socket: it must reply to a client that has no IP/ARP entry yet and honour
  the broadcast flag), building/parsing IPv4+UDP itself (with checksums) and a classic-BPF filter for UDP
  dport 67, the same cooked-`SOCK_DGRAM` approach `pkg/ndproxy`'s `packet.go` uses. `server.go`'s
  `New([]InterfaceConfig)` validates every pool and opens every socket *synchronously* (so a bad subnet or a
  socket failure fails `cmd/minuteman`'s startup instead of surfacing only in a background log line), and the
  returned `*Server`'s `Serve(ctx)` runs one goroutine + `Pool` per interface, propagating a worker's runtime
  read error rather than swallowing it (a fake `conn` makes that testable). See the `xdp_dslite_encap`
  `is_non_unicast_dst` bypass above for why the datapath had to change before any of this could receive a
  packet.
- **`cmd/minuteman/main.go`** — thin CLI entrypoint. Flags: `-wan`, `-b4`, `-aftr` (optional — see below),
  repeatable `-lan iface=gatewayIP[/prefixlen][,mtu]` (the `/prefixlen`, default `/24`, is the DHCPv4
  subnet), `-wan-dst-mac` (fallback only), `-stats-interval`, `-dhcpv6-pd`
  (opt-in prefix delegation), `-ndproxy` (opt-in RFC 4389 proxying, mutually exclusive with `-dhcpv6-pd` —
  validated in `run()` before anything else happens), `-dns-proxy` (opt-in DNS proxy, orthogonal to both
  IPv6-provisioning flags) with repeatable `-dns-server` to override its upstreams, `-dhcpv4` (opt-in DHCPv4
  server, orthogonal to everything else) with `-dhcpv4-lease` and repeatable `-dhcpv4-dns`,
  `-ipv6-sw-rss` (opt-in native-IPv6 software-RSS cpumap fanout — off by default, for NICs whose hardware
  RSS can't spread flows; when set, `run()` calls `dp.EnableIPv6SoftwareRSS(onlineCPUs())` after WAN/LAN
  attach, once every egress ifindex is registered in `tx_ports`),
  `-hb46pp-vendor-id`/`-hb46pp-product`/`-hb46pp-version`
  (HB46PP client-identity query parameters — see below; default to the documentation OUI `acde48` since
  minuteman has no IEEE OUI, overridable since a VNE may key rollout/workaround decisions off them, not just
  statistics). Flag-value
  parsing (`LANSpec`/`LANSpecList`, `AddrList`, MAC parsing) lives in `internal/cliconfig`, not in `main.go` itself.
  `resolveAFTR()` returns `-aftr` parsed directly if given (in which case its second return, the DNS
  servers `-dns-proxy` defaults to using, is nil — that path skips the DHCPv6 exchange entirely), otherwise
  blocks on `pkg/aftrdiscovery.Discover`
  using the same lifecycle context as `SIGINT`/`SIGTERM` handling (no artificial timeout — indefinite
  RFC 3315 retry is correct here, since there's no working DS-Lite path without an AFTR anyway). On
  `aftrdiscovery.ErrNoAFTRName` it falls back to `hb46pp.Discover` (capability `dslite` only, DNS servers
  from the partial DHCPv6 result, client identity from the three `-hb46pp-*` flags bundled into an
  `hb46ppIdentity`), looping the whole DHCPv6→HB46PP chain with `hb46pp.RetryDelay`-paced sleeps on HB46PP
  failure — same block-until-success-or-ctx-cancel stance, but at the spec's backoff cadence so a real
  VNE's provisioning server isn't hammered. When `-dhcpv6-pd` is set, `runPrefixDelegation()` similarly blocks
  on `pkg/prefixdelegation.Acquire`, then applies the initial LAN assignment via
  `internal/lanprefix.Reconcile` synchronously (before the datapath is considered "up"), syncs an
  `internal/lanprefix.RAManager` against the result (starting one `pkg/routeradvert.Serve` goroutine per
  `-lan` interface, also tracked on the same `sync.WaitGroup`), then starts `pkg/prefixdelegation.Maintain`
  in a background goroutine (tracked on that `sync.WaitGroup` that `run()` waits on before returning, so a
  shutdown's best-effort `Release` and every RA worker's best-effort final advertisement all get a chance
  to finish) with that same `Reconcile`+`RAManager.Sync` pair as its `onLeaseChange` callback. When
  `-ndproxy` is set instead, `runNDProxy()` is a thin wrapper that hands the `-lan` interface names straight
  to `internal/wanextend.Serve`, which owns the whole flow itself (see that package's own entry below) and
  registers every goroutine it starts on the same `sync.WaitGroup` as the `-dhcpv6-pd` path, for the same
  shutdown-draining reason. If `-dns-proxy` is set, `startDNSProxy()` opens `pkg/dnsproxy` (via
  `dnsproxy.Listen`, *synchronously*, so a bind failure fails `run()`) listening on every `-lan`
  interface's IPv4 gateway IP *and* its own link-local IPv6 address, forwarding to `-dns-server` if any
  were given or else the DNS servers `resolveAFTR()` returned; `run()` fails fast before any of this if
  `-dns-proxy` is set but no DNS servers are available from either source. It's started *before*
  `runPrefixDelegation`/`runNDProxy` and returns the map of `-lan` interface → the link-local address it
  actually bound; that map is passed to those two so their RA workers advertise an RFC 8106 RDNSS option
  (RFC 7084 §L-4, so an IPv6-only SLAAC client gets a DNS server) pointing *only* at addresses this proxy
  really bound — never a DNS server nothing answers on. A LAN link-local still DAD-tentative at bind time
  (`EADDRNOTAVAIL`) is retried on the tentative cadence; any other bind error (port 53 in use, etc.) fails
  immediately. If `-dhcpv4` is set, `runDHCPv4()` builds one `pkg/dhcpv4.InterfaceConfig`
  per `-lan` (subnet from its `/prefixlen`, gateway as router; DNS = `-dhcpv4-dns`, else the gateway when
  `-dns-proxy` runs, else omitted; MTU = the `-lan` MTU or else the WAN MTU minus the 40-byte tunnel
  overhead, dropped if below the IPv4 minimum) and constructs the server with `pkg/dhcpv4.New` *synchronously*
  so a bad subnet or socket failure fails startup, then runs it; `run()` also rejects a `-dhcpv4-lease`
  shorter than `minDHCPv4Lease`. All these background goroutines are tracked on the same `sync.WaitGroup`.
  Otherwise `main.go` just orchestrates
  `pkg/datapath.Loader` calls (`Load`/`AttachWAN`/`SetB4Config`/`AttachLAN`+`SetLANConfig` per `-lan`/`Stats`
  on a timer) — it never touches `cilium/ebpf` or BPF map layouts directly.
- **`internal/cliconfig`** — parses `minuteman`'s flag values (`LANSpec` — now also carrying the optional
  DHCPv4 `Subnet` from the `-lan` value's `/prefixlen` — `ParseLANSpec`, `LANSpecList`
  implementing `flag.Value`, `AddrList` implementing `flag.Value` for a repeatable plain IP-address flag
  like `-dns-server`/`-dhcpv4-dns`, `ParseMAC`) into typed values for `main.go` to hand to `pkg/datapath`. Thin
  CLI-flag glue only, not a home for protocol logic (that's `pkg/dhcpv6`/`pkg/aftrdiscovery`/`pkg/hb46pp`/
  `pkg/prefixdelegation`).
- **`internal/lanprefix`** — the DHCPv6-PD *policy* layer: what to do with a delegated prefix, as opposed to
  the protocol client itself (`pkg/prefixdelegation`). `carve.go`'s `SubnetFor(delegated, index)`/
  `AssignedAddress(subnet)` are pure functions (bit manipulation on a `netip.Prefix`'s first 8 bytes, no
  I/O) that carve one `/64` per `-lan` interface's position in the flag list out of the delegated prefix and
  pick its `::1` address. `reconcile.go`'s `Reconcile()` opens a `pkg/netlink.Socket` and ties it together
  per LAN interface, removing a stale address first (`DelAddr`) if a renewal changed which `/64` it should
  have, then assigning the new one (`AddAddr`, `NLM_F_REPLACE`-idempotent) — skipping both calls entirely
  when the subnet is unchanged since the last `Reconcile`, to avoid transient route churn — and also returns
  each interface's `ValidLifetime`/`PreferredLifetime` (taken from the delegated prefix, not derived) on the
  resulting `Assignment` for `ra.go` to consume. `ra.go`'s `RAManager` drives one `pkg/routeradvert.Serve`
  goroutine per LAN interface from those `Assignment`s (`OnLink: true`, since a PD delegation really is
  distinct per LAN interface): `Sync()` always restarts a LAN interface's worker on every call (not just
  when its `Subnet` changes), since a Renew resets the lifetimes even when the subnet itself doesn't change
  and a long-running `Serve` goroutine has no other way to pick that up — restarting is cheap, unlike
  `Reconcile`'s netlink unchanged-skip optimization above, which exists to avoid churn restarting an RA
  sender doesn't have an equivalent of.
- **`internal/wanextend`** — the NDProxy *policy* layer, mirroring `internal/lanprefix`'s split from its
  protocol client (`pkg/ndproxy`) but for the single-shared-WAN-`/64` model instead of a distinct PD
  delegation. `discover.go`'s `DiscoverPrefix(ctx, wanIfindex)` blocks, polling `pkg/netlink.Socket.Addrs`
  every `prefixPollInterval`, until the WAN interface has a global-scope SLAAC address to report (masked to
  its network) — RA/SLAAC lands asynchronously sometime after `AttachWAN`/`SolicitRouters`, and there's
  nothing to extend onto the LAN until it does. Unlike `internal/lanprefix`'s delegated prefix,
  there's no DHCPv6-style T1/T2 renewal ladder to drive here — the kernel just manages its own address
  lifetimes off whatever RAs happen to arrive — so re-learning is `WatchChanges(ctx, wanIfindex, current,
  onChange)` instead: it re-polls every `watchPollInterval` (5 minutes, a CPE-local policy choice — WAN
  renumbering is rare and RFC 4861 mandates no cadence for noticing it) and calls `onChange` only when a
  reading is a genuine, valid difference from `current`; a transient read error or a momentarily-absent
  global address (expected mid-renumbering) is not itself reported, so the last-known prefix keeps being
  advertised until a real replacement is confirmed. That change/no-change decision is `nextWatchState`, split
  out as a pure function precisely so it's unit-tested without a real clock or netlink socket
  (`discover_test.go`) — the same rationale `pkg/ndproxy`'s `proxyState` takes an explicit `now` instead of
  reading the clock. Neither `DiscoverPrefix` nor `WatchChanges` track `IFA_CACHEINFO`'s remaining
  lifetimes, so `ra.go` re-advertises to the LAN with RFC 4861 §6.2.1's recommended default lifetimes
  rather than the WAN RA's actual ones — a known simplification. `ra.go`'s `raManager` drives one
  `pkg/routeradvert.Serve` goroutine per LAN interface, all broadcasting the same prefix (`OnLink: false`)
  — unlike `internal/lanprefix.RAManager`, which advertises a distinct subnet per interface from an
  `Assignment` list, NDProxy extends one shared prefix onto every LAN interface uniformly, so `sync()` takes
  a single `netip.Prefix` rather than a per-interface list; it always restarts every worker on each call,
  the same "restarting is cheap" reasoning `internal/lanprefix.RAManager.Sync` uses. `hostroutes.go`'s
  `HostRoutes` wraps a `pkg/netlink.Socket` for the lifetime of one `pkg/ndproxy.Serve` run, matching its
  `Config.OnActive`/`OnInactive` callback shapes: `Install` adds a `/128` route to a confirmed-active target
  out its LAN interface (`AddRoute`, so the kernel's own forwarding decision picks the right `-lan`
  interface when there's more than one — without it, WAN-side proxying alone doesn't tell the kernel which
  LAN interface to actually forward through); `Remove` (`OnInactive` has no error return, unlike `OnActive`)
  deletes it best-effort, logging rather than propagating a failure, since a route that outlives its target
  is stale but harmless and gets overwritten (`NLM_F_REPLACE`) the next time `Install` runs for it.
  `serve.go`'s `Serve(ctx, wanIface, wanIfindex, lanIfaces, wg)` is the single entry point `cmd/minuteman`
  calls for `-ndproxy`: blocks on the initial `DiscoverPrefix` (nothing else can usefully start before
  then, the same rationale `runPrefixDelegation` applies to its own initial `Acquire`), then starts
  `pkg/ndproxy.Serve`, the initial `raManager.sync`, and a `WatchChanges` goroutine whose `onChange`
  re-runs `raManager.sync` with the new prefix — every goroutine registered on the caller's `wg`.

When implementing new functionality, follow this split: per-packet fast-path logic goes in
`bpf/datapath.bpf.c`; anything that needs `cilium/ebpf` or knows about BPF map layouts goes in
`pkg/datapath`; generic protocol/wire-format code goes in its own `pkg/` package the way
`pkg/dhcpv6`/`pkg/aftrdiscovery`/`pkg/hb46pp`/`pkg/prefixdelegation`/`pkg/routeradvert`/`pkg/ndproxy`/
`pkg/netlink`/`pkg/dnsproxy`/`pkg/dhcpv4` do; CLI-specific glue and policy decisions belong in `internal/` or `cmd/` (e.g.
`internal/lanprefix`'s delegated-prefix-to-LAN-address and delegated-prefix-to-RA policy, or
`internal/wanextend`'s WAN-prefix-discovery-to-RA and confirmed-target-to-host-route policy), calling into
the `pkg/` packages rather than duplicating their logic.

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
