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
and `internal/lanprefix` carves one `/64` per `-lan` interface from it and assigns it via `pkg/netlink`
(hand-rolled `golang.org/x/sys/unix` netlink I/O, no netlink library or `ip` exec). `internal/lanprefix`
also now drives Router Advertisements (RFC 4861) out each `-lan` interface via the `pkg/routeradvert`
package, so LAN clients can SLAAC an address out of the assigned `/64` themselves — LAN clients get both
the DS-Lite IPv4 path and native IPv6 out of the delegated prefix.

NDProxy (RFC 4389) is also implemented, behind `-ndproxy`, for the alternative model some ISPs use instead
of DHCPv6-PD: a single `/64` handed out on the WAN link itself, with the CPE expected to extend that same
`/64` onto the LAN rather than being delegated a distinct prefix for it. `pkg/ndproxy` answers Neighbor
Solicitations arriving on the WAN link on behalf of LAN hosts, but — unlike a passive-snooping proxy —
only after actively verifying via a Neighbor Solicitation probe on the LAN side that the target host
genuinely exists right now (`pkg/ndproxy.Serve`'s `proxyState` machine); `internal/wanextend` is the
policy layer around it: `DiscoverPrefix` learns the WAN's own SLAAC `/64` via `pkg/netlink` and
`WatchChanges` keeps polling for it changing afterwards (an ISP renumbering the WAN link), re-advertising
it on every `-lan` interface with the On-Link flag cleared (`routeradvert.Config.OnLink`) so LAN clients
route everything through the CPE rather than assuming direct link-layer reachability, and
`HostRoutes` installs/removes a per-target `/128` route via `pkg/netlink` as `pkg/ndproxy.Serve` confirms
or expires each target, so the kernel's own forwarding decision picks the right `-lan` interface when
there's more than one. `-ndproxy` and `-dhcpv6-pd` are mutually exclusive (they're alternative WAN IPv6
provisioning models, not composable).

A DNS proxy (RFC 6333's B4 SHOULD) is also implemented, behind `-dns-proxy`, orthogonal to both of the
above: `pkg/dnsproxy.Serve` listens on every `-lan` interface's gateway IP (port 53, UDP and TCP) and
forwards each query verbatim to upstream DNS server(s) — `-dns-server`, or, if that's omitted, the DNS
servers `resolveAFTR` already learned via the DHCPv6 Information-Request it performs for AFTR discovery
(`aftrdiscovery.Result.DNSServers`) — relaying the answer back unmodified. The package never parses a DNS
message at all, just relays bytes, so it's opaque to (and correct regardless of) whatever record types or
EDNS0 options a query/answer carries. Forwarding goes out as an ordinary native-IPv6 socket call from the
CPE's own process, so it structurally can't be routed through `xdp_dslite_encap`/`decap` (those only ever
see LAN-originated IPv4 or WAN-arriving AFTR-tunneled traffic, neither of which this is) — verified live
against the netns rig (see below) by capturing on the AFTR's own decap interface during a DNS-proxied
query and confirming zero packets arrive there. `-dns-proxy` requires at least one DNS server from either
source; `run()` fails fast at startup if none are available (e.g. `-aftr` was given directly, skipping
DHCPv6 discovery entirely, and no `-dns-server` was given either).

A DHCPv4 server (RFC 2131/2132) is also implemented, behind `-dhcpv4`, orthogonal to all of the above: it
hands LAN clients the private IPv4 address the DS-Lite softwire carries (`pkg/dhcpv4`). Each `-lan`
interface serves its own subnet — taken from the `-lan` value's optional `/prefixlen` (default `/24`) — with
its gateway IP as the offered router and (by default) DNS server, pointing clients at this CPE, i.e.
`-dns-proxy`; `-dhcpv4-dns` overrides the DNS offered. The advertised interface MTU (option 26) is the WAN
MTU minus the 40-byte DS-Lite tunnel overhead (or the explicit `-lan` MTU if set), so LAN clients size
packets to fit the softwire. Getting DHCP to the server needed a *datapath* change: a DHCP DISCOVER/REQUEST
is sent to the limited-broadcast address, and `xdp_dslite_encap` (attached to the LAN interface, running
before minuteman's own AF_PACKET DHCP socket) was wrapping it into the softwire like any other IPv4 packet.
`xdp_dslite_encap` now bypasses (`XDP_PASS`) non-unicast IPv4 destinations (limited broadcast + multicast,
`is_non_unicast_dst`) — which is correct in its own right, since a point-to-point softwire to one AFTR must
never carry broadcast/multicast — so those packets reach the local stack and the DHCP server; unicast DHCP
renewals to the gateway were already bypassed by `is_local_gateway_dst`. Verified end-to-end against the
netns rig with a real `dhclient` (DORA, the pool's first address, the gateway default route, and the
DS-Lite-adjusted MTU all applied, then the DS-Lite data path exercised over that DHCP-assigned config).

`internal/` holds `cliconfig` (CLI flag parsing), `lanprefix` (DHCPv6-PD LAN policy, including RA
serving), and `wanextend` (NDProxy LAN policy, including RA serving and host-route management);
`pkg/dhcpv6`/`pkg/aftrdiscovery`/`pkg/hb46pp`/`pkg/prefixdelegation`/`pkg/routeradvert`/`pkg/ndproxy`/
`pkg/netlink`/`pkg/dnsproxy`/`pkg/dhcpv4` are the reusable protocol packages.

Also not yet implemented: the migration technologies other than DS-Lite that an HB46PP response can
describe (`map_e`/`map_t`/`lw4o6`/`464xlat`/`ipip`). `pkg/hb46pp` already decodes the response's
`order`-ranked technology list and preserves those technologies' parameter objects raw
(`json.RawMessage` fields on `hb46pp.Provisioning`), so implementing one of them means adding its typed
parameter struct there, its datapath, and extending `cmd/minuteman`'s policy beyond the current
dslite-only capability request. Also not acted on yet: periodic re-discovery — both
`aftrdiscovery.Result` and `hb46pp.Result` report their refresh interval (RFC 4242's, and HB46PP's
`ttl`/20-24h default, respectively), and `hb46pp.Result.Provisioning.Token` is decoded but never echoed
back on a later request, but `cmd/minuteman` discovers once at startup and never re-runs discovery.
Implementing this needs more than a timer: RFC 3315 says re-discovery should also trigger on the WAN
address changing, and the harder part is applying a *changed* AFTR to the live datapath safely (today
`SetB4Config` is only ever called once, before the datapath is considered "up") without disrupting
in-flight softwire traffic.

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

How the LAN gets IPv6 reachability is a separate, orthogonal choice, selectable via `MM_WAN_MODEL`:
- `dhcpv6-pd` (default): Kea's `subnet6` includes a `pd-pools` entry delegating `PD_POOL_PREFIX`, and
  `run-cpe.sh`/`smoketest.sh` start minuteman with `-dhcpv6-pd`, exercising `pkg/prefixdelegation` +
  `internal/lanprefix` end-to-end (the existing DHCPv6-PD + RA/SLAAC checks below).
- `ndproxy`: Kea's `subnet6` omits `pd-pools` entirely (this mode's whole premise is an ISP that hands out
  no distinct delegation), and the scripts start minuteman with `-ndproxy` instead. `mm-isp`'s dnsmasq RA
  on the WAN link (already running regardless of `MM_WAN_MODEL`, for both AFTR discovery and this) is what
  minuteman's `internal/wanextend.DiscoverPrefix` learns `WAN_PREFIX` from; `smoketest.sh` then confirms the
  actual RFC 4389 proxying behavior by having `mm-isp` — L2-adjacent to `mm-cpe`'s WAN link and itself the
  origin of the on-link `WAN_PREFIX` RA there — ping `mm-host`'s SLAAC'd address directly: that only
  succeeds if minuteman's `pkg/ndproxy` intercepted the resulting Neighbor Solicitation on the WAN link,
  actively verified `mm-host` via an LAN-side probe, answered on its behalf, and `internal/wanextend
  .HostRoutes` installed the resulting host route. `setup.sh` also disables RFC 4941 privacy addresses on
  `mm-host` (`use_tempaddr=0`) so there's exactly one deterministic SLAAC address for `smoketest.sh` to
  target this way. `setup.sh` records the mode in `$RUNDIR/wan-model` so `run-cpe.sh`/`smoketest.sh` start
  minuteman with the matching flag and `smoketest.sh` asserts the matching checks.

A third, independent toggle, `MM_DNS_PROXY` (`0` default or `1`), adds `-dns-proxy` to the minuteman
invocation (`run-cpe.sh`/`smoketest.sh` read `$RUNDIR/dns-proxy-enabled`, matching the other two toggles'
own state-file pattern). It needs only a DNS server address, which Kea's `dns-servers` option-data always
provides regardless of `MM_AFTR_DISCOVERY`/`MM_WAN_MODEL`, so it composes with either. `smoketest.sh` has
`mm-host` `dig` the AFTR-Name `A`/`AAAA` record — the same one `mm-isp` itself answers directly for the
AFTR-discovery checks above — through minuteman's LAN gateway IP instead, over both UDP and TCP, and
checks the answer matches; a live run also confirmed via `tcpdump -i dslite0` on `mm-aftr` that zero
packets cross the softwire during a DNS-proxied query (see `pkg/dnsproxy`'s own entry in Architecture for
why that's structurally guaranteed, not just empirically true this once).

A fourth, independent toggle, `MM_DHCPV4` (`0` default or `1`), adds `-dhcpv4` and exercises the DHCPv4
server. Because a LAN client can no longer be given a static IPv4 (it must obtain one from the server),
`setup.sh` in this mode leaves `mm-host` without a static address or default route, and `smoketest.sh` — as
its very first check, before anything else assumes the host has IPv4 — runs a real `dhclient` in `mm-host`
to acquire them, then asserts the pool's first address (`.2`), the gateway default route, and the
DS-Lite-adjusted interface MTU (`1460`, from option 26) all landed; every later check (DNS proxy, the
DS-Lite data path) then runs over that DHCP-assigned config, so the whole rig doubles as an end-to-end
DHCPv4 test. `dhclient` is given a small conf requesting `interface-mtu` so it applies option 26.
`teardown.sh` also stops any `dhclient` left running in `mm-host`.

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
The full smoketest (AFTR discovery, LAN IPv6 reachability, LAN IPv4 provisioning, and the DS-Lite data path
end-to-end through the AFTR's decap+NAPT44 to the simulated internet and back, ICMP and TCP) has been
verified passing from a fresh setup for `MM_AFTR_DISCOVERY=dhcpv6`/`hb46pp` (both against the `dhcpv6-pd`
WAN model), for `MM_WAN_MODEL=dhcpv6-pd`/`ndproxy` (both against `dhcpv6` AFTR discovery), for
`MM_DNS_PROXY=1`, and for `MM_DHCPV4=1` (both against `dhcpv6`/`dhcpv6-pd`); the default (all four toggles
off) was also re-run after the `xdp_dslite_encap` non-unicast-bypass change to confirm no regression. The
uncrossed corners of the four independent axes haven't each been re-run, but they are independent code
paths (AFTR discovery, LAN IPv6 provisioning, DNS forwarding, LAN IPv4 provisioning) with no shared state.

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
  socket I/O, correctness here is exercised by `test/netns`, not `go test`). `serve.go`'s
  `Serve(ctx, Config)` opens a UDP `net.ListenUDP` and TCP `net.ListenTCP` socket per `Config.ListenAddrs`
  (port 53), closing every socket on `ctx.Done()` to unblock `serveUDP`/`serveTCP`'s read loops — the same
  close-to-unblock shutdown pattern `pkg/ndproxy`'s `conn`/`packetConn` use. `udp.go`'s `serveUDP` spawns
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
  single-subnet-per-interface case a home CPE serves (no BOOTP relay/`giaddr` forwarding, no shared
  networks, no restart persistence — an in-memory pool). Follows the same pure-vs-I/O split as `pkg/ndproxy`:
  `message.go`/`options.go` are the BOOTP + magic-cookie + option TLV wire codec; `lease.go`'s `Pool` is the
  address allocator (sticky-per-client offers, lowest-free allocation, expiry, RELEASE/DECLINE), pure with
  an explicit `now time.Time` like `ndproxy`'s `proxyState`; `handler.go`'s `handle` is the pure DORA +
  RELEASE/DECLINE/INFORM decision (request → reply message, or nil to stay silent) — all three unit-tested
  with no sockets. `packet.go` is the raw AF_PACKET I/O (a DHCP server can't use an ordinary UDP socket: it
  must reply to a client that has no IP/ARP entry yet and honour the broadcast flag), building/parsing
  IPv4+UDP itself (with checksums) and a classic-BPF filter for UDP dport 67, the same cooked-`SOCK_DGRAM`
  approach `pkg/ndproxy`'s `packet.go` uses; `server.go`'s `Serve(ctx, []InterfaceConfig)` runs one
  goroutine + socket + `Pool` per LAN interface. See the `xdp_dslite_encap` `is_non_unicast_dst` bypass
  above for why the datapath had to change before any of this could receive a packet.
- **`cmd/minuteman/main.go`** — thin CLI entrypoint. Flags: `-wan`, `-b4`, `-aftr` (optional — see below),
  repeatable `-lan iface=gatewayIP[/prefixlen][,mtu]` (the `/prefixlen`, default `/24`, is the DHCPv4
  subnet), `-wan-dst-mac` (fallback only), `-stats-interval`, `-dhcpv6-pd`
  (opt-in prefix delegation), `-ndproxy` (opt-in RFC 4389 proxying, mutually exclusive with `-dhcpv6-pd` —
  validated in `run()` before anything else happens), `-dns-proxy` (opt-in DNS proxy, orthogonal to both
  IPv6-provisioning flags) with repeatable `-dns-server` to override its upstreams, `-dhcpv4` (opt-in DHCPv4
  server, orthogonal to everything else) with `-dhcpv4-lease` and repeatable `-dhcpv4-dns`,
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
  shutdown-draining reason. If `-dns-proxy` is set, `runDNSProxy()` starts `pkg/dnsproxy.Serve` listening on
  every `-lan` interface's gateway IP, forwarding to `-dns-server` if any were given or else the DNS servers
  `resolveAFTR()` returned; `run()` fails fast before any of this if `-dns-proxy` is set but no DNS servers
  are available from either source. If `-dhcpv4` is set, `runDHCPv4()` builds one `pkg/dhcpv4.InterfaceConfig`
  per `-lan` (subnet from its `/prefixlen`, gateway as router and — unless `-dhcpv4-dns` overrides — DNS,
  MTU = the `-lan` MTU or else the WAN MTU minus the 40-byte tunnel overhead) and starts `pkg/dhcpv4.Serve`;
  all these background goroutines are tracked on the same `sync.WaitGroup`. Otherwise `main.go` just
  orchestrates
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
