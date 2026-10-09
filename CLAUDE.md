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
  (RFC 3736 + RFC 6334 `OPTION_AFTR_NAME`) with an HB46PP (JAIPA v6mig-1) fallback, so minuteman needs no
  per-VNE configuration and spawns no external DHCP/DNS daemon. There are **two** routes to that fallback,
  and they differ in where its resolvers come from: a Reply that carries no AFTR-Name hands HB46PP the DNS
  servers that same Reply carried, while an Information-Request that draws *no reply at all* within
  `informationRequestTimeout` (30s) hands it the DHCPv6-PD lease's servers instead — which is why `run()`
  acquires that lease *before* AFTR discovery (see `cmd/minuteman/main.go` below). The bound exists because
  RFC 3315 §18.1.5 sets no maximum retransmission count or duration, so `pkg/dhcpv6` would otherwise retry
  forever against a network that never answers — and two access tiers of the NTT East FLET'S IPoE spec
  state outright that theirs doesn't (光クロス §4.4.2.1.2, 光25G §2.4.1.1.2), which are exactly the
  deployments HB46PP serves. Re-discovery is periodic (RFC 4242 refresh) and, with a dynamic B4 (below),
  also triggered by a WAN address change (the DS-Lite B4-address change of RFC 7785) — a changed AFTR
  migrates gracefully (in-flight flows kept on the old AFTR until they drain), a changed B4 hard-switches.
- **Dynamic B4** (automatic unless `-b4` is given) — the B4's own softwire source is selected from the
  WAN's kernel-chosen source toward the AFTR (RFC 6724, via an `RTM_GETROUTE`/`RTA_PREFSRC` query) and
  re-selected when the WAN address changes (renumbering/lease/reconnect), so the softwire survives a WAN
  renumbering instead of needing a restart. `-b4` still pins it statically.
- **DHCPv6 Prefix Delegation** (`-dhcpv6-pd`, RFC 3633) — acquires and maintains a delegated prefix,
  carves one `/64` per `-lan` interface from it, and RAs it out (RFC 4861) for LAN SLAAC. Renewal runs on
  the server's T1/T2, or — when the server sends 0 to leave that timing to the requesting router — on
  timers derived from the prefix's own preferred lifetime (RFC 9915 §14.2, see `pkg/prefixdelegation`).
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
- **Softwire fragmentation** (always on; RFC 6333 §5.3, both halves) — *outbound*, an oversized inner
  IPv4 packet, **DF or not** (errata 5847 → RFC 2473 §7.2(b) ignores the DF bit), is encapsulated whole
  and the **outer IPv6** is fragmented *in XDP* (`encap_fragment_outer`: one `BPF_F_BROADCAST` devmap
  clone per possible fragment, each trimmed to fragment *i* by an `xdp_softwire_frag<i>` program and
  redirected out the WAN; the clones bounce through one large-MTU companion veth pair per fragment index,
  `internal/fragpath`'s `mm-frag<i>`/`mm-frag<i>p` — the architecture section explains why per-fragment
  *devices* are load-bearing). The encap-side ICMPv4 Fragmentation-Needed is gone with this: an oversized
  DF packet is fragmented transparently instead of bouncing a PMTUD signal. *Inbound*, a fragmented
  softwire IPv6 packet is `XDP_PASS`ed to a kernel companion `ip6tnl` (`internal/slowpath`,
  local=B4/remote=AFTR, mode ipip6, encaplimit none) plus an IPv4 default route through it: the kernel
  reassembles before the ip6tnl decapsulates (§5.3's "reassembly MUST happen before decapsulation"). The
  ip6tnl also remains the *fallback* for what the XDP fragmenter can't take (`STAT_ENCAP_FRAG_SLOW`: >4
  fragments, inner beyond `fragpath.MaxInnerLen`, degenerate MTU — there the kernel fragments the inner
  IPv4, a reachability fallback, not §5.3 conformance; backlog §1's residual note) and for a decapped
  inner too big for a non-DF LAN egress. Created at startup and repointed on an AFTR migration /
  B4 switch. A side benefit is that the IPv4 default route lets the kernel answer ICMPv4 Time Exceeded for
  an expiring inner TTL outbound. To keep that default route from turning the decap
  path into a reflector, a decapped inner IPv4 that the FIB resolves off-LAN (back toward the companion
  tunnel) is dropped in XDP (`STAT_DECAP_MARTIAN`) rather than passed to the kernel.
- **Tunnel ICMPv6 relay + learned softwire path MTU** (always on; RFC 2473 §8/§6.7) — an ICMPv6 error an
  intermediate router on the B4↔AFTR path sends *about a softwire packet* (Packet Too Big, Time Exceeded,
  Destination Unreachable) is translated in XDP into an ICMPv4 error toward the LAN client whose packet it
  quoted (`handle_tunnel_icmpv6`, RFC 7915 §5.3's type table, sourced from `192.0.0.2`), and a Packet Too
  Big also records a softwire path MTU the encap side's own `bpf_check_mtu` can never see — it only knows
  the local WAN device. Encap clamps against that reading per packet; the fragment size and the companion
  ip6tnl's MTU are re-derived from it by userspace (`cmd/minuteman`'s `watchTunnelPMTU`), because the
  fragmenter's two halves read `frag_unit` at different moments and a value that changed in between would
  produce an unreassemblable fragment set. A Packet Too Big about a *non-DF* packet is consumed rather than
  relayed: the answer there is to fragment at the learned MTU, not to push the problem back.
- **TCP MSS clamping** (`-tcp-mss-clamp`, default `auto`) — a TCP SYN crossing the softwire has its
  advertised MSS lowered in XDP (`clamp_tcp_mss`) to what the softwire can carry, so TCP never offers
  segments the fragmenter would have to carve up. Not an RFC requirement — it's the middlebox workaround
  RFC 4459 §3 lists among the four tunnel-MTU strategies, and it rewrites forwarded traffic — but it earns
  its keep twice: PMTUD fails outright wherever the ICMP it depends on is filtered, and TCP is the bulk of
  what would otherwise land on the comparatively expensive clone-and-trim fragmenter. Applied on **both**
  paths, since the MSS option announces what its own *sender* will receive: encap clamps the LAN client's
  SYN (bounding what arrives through the softwire) and decap clamps the remote's SYN-ACK (bounding what the
  LAN client sends into it). Only ever lowers a value, never raises one. `auto` derives the clamp from the
  softwire MTU and tracks a learned path MTU; an explicit MSS pins it; `off` disables it.
- **Tunnel-originated ICMPv4** (always on; RFC 1812 §5.3.1 + §4.3.2.7, RFC 6333 §5.7 / RFC 7335) — the
  ICMPv4 errors the B4 itself originates back through the softwire (Fragmentation Needed on the decap
  path, and now Time Exceeded for an inner TTL that expires *inbound*, `STAT_ICMP_TIME_EXCEEDED`) are
  sourced from the well-known B4 address `192.0.0.2` rather than a LAN gateway address, and are gated on
  the packet genuinely being forwarded and on §4.3.2.7's suppression rules — see the `xdp_dslite_decap`
  bullet in Architecture for where each check sits.

All of the above has been verified end-to-end against the netns rig (see Testing below).

`internal/` holds `cliconfig` (CLI flag parsing), `lanprefix` (DHCPv6-PD LAN policy, including RA
serving), `wanextend` (NDProxy LAN policy, including RA serving and host-route management), `slowpath`
(the DS-Lite companion `ip6tnl` lifecycle for softwire reassembly + fragmentation fallback), and
`fragpath` (the companion veth pairs the in-XDP softwire fragmenter bounces its clones through);
`pkg/dhcpv6`/`pkg/aftrdiscovery`/`pkg/hb46pp`/`pkg/prefixdelegation`/`pkg/routeradvert`/`pkg/ndproxy`/
`pkg/netlink`/`pkg/dhcpv4`/`pkg/ethtool` are the reusable protocol packages (and `internal/dnsproxy`, all I/O, runs as a molecule supervision tree). Every package under both
trees carries its own `README.md` covering its rationale in more depth than the Architecture section
below, indexed by `internal/README.md` and `pkg/README.md`.

Not yet implemented:
- The migration technologies other than DS-Lite that an HB46PP response can describe (`map_e`/`map_t`/
  `lw4o6`/`464xlat`/`ipip`). `pkg/hb46pp` already decodes the response's `order`-ranked technology list
  and preserves those technologies' parameter objects raw (`json.RawMessage` on `hb46pp.Provisioning`),
  so implementing one means adding its typed parameter struct there, its datapath, and extending
  `cmd/minuteman`'s policy beyond the current dslite-only capability request.
- A handful of RFC 7084/6333 compliance gaps. Softwire fragmentation (RFC 6333 §5.3) is now addressed on
  both halves (in-XDP outer-IPv6 fragmentation + kernel-ip6tnl reassembly — see the **Softwire
  fragmentation** feature above); only its fallback cases (backlog §1's residual note) still fragment the
  inner IPv4. The remaining gaps are in `docs/rfc-compliance-backlog.md`, priority-ordered with the
  specific code each points at. Non-protocol operability/test-ergonomics improvements are tracked
  separately in `docs/operability-backlog.md` — its #1 (out-of-band stats via a bpffs-pinned map + the
  `minuteman stats` subcommand) is done, #2 (daemon/detach) partially (systemd unit example +
  `-pidfile`; no `sd_notify`), #3 (per-packet capture) partially: the datapath carries the
  xdpcap-compatible hooks and pins them, but there's no in-tree capture client yet.

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

Ten independent env-var toggles select what `setup.sh` builds and what `smoketest.sh` asserts —
`MM_AFTR_DISCOVERY` (`dhcpv6`/`hb46pp`), `MM_WAN_MODEL` (`dhcpv6-pd`/`ndproxy`), `MM_DNS_PROXY`,
`MM_DHCPV4`, `MM_DUALSTACK`, `MM_IPV6_SW_RSS`, `MM_DYNAMIC_B4` (omit `-b4` and drive a WAN-renumbering
scenario), `MM_SOFTWIRE_FRAG` (exercise softwire fragmentation both ways — oversized non-DF *and* DF
pings outbound, both expected to round-trip via the in-XDP outer-IPv6 fragmenter, and a hand-crafted
fragmented softwire packet inbound via `send-softwire-fragments.py`), `MM_PD_ZERO_TIMERS` (have Kea
delegate with T1=T2=0 on short lifetimes, so the client-derived renewal timer is asserted and a real
renewal is waited out — adds ~90s), `MM_TUNNEL_ICMP` (inject each ICMPv6-error-about-a-softwire type and
assert the relayed ICMPv4, then narrow the ISP↔AFTR core link so a *real* Packet Too Big is drawn and the
learned path MTU is asserted to reach both the fragmenter and the companion ip6tnl; runs last, since a
learned MTU lingers 10 minutes and would re-size what `MM_SOFTWIRE_FRAG` asserts on) — plus the full list of
verified-passing combinations. See
**`test/netns/README.md`** for all of that detail; it's a rig-operation runbook, not something most tasks
need loaded up front.

`run-cpe.sh` and `smoketest.sh` deliberately omit `-aftr` so minuteman discovers it live against the rig —
pass `-aftr <addr>` as an extra argument to either script to override with a static address instead.

Datapath counters are read out-of-band via `minuteman stats [--json]` against the bpffs-pinned stats map
(`smoketest.sh`'s assertions do this as before/after deltas through its `read_stat` helper); both scripts
launch minuteman via `nsenter --net`, *not* `ip netns exec`, because the latter's `/sys` remount would
strand that pin on an invisible bpffs — see the README's "Reading datapath stats" before changing how
minuteman is launched.

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
    accounting for the 40-byte IPv6 encap overhead (`TUNNEL_L3_OVERHEAD`): a too-big inner packet — **DF
    or not** (RFC 6333 §5.3 / errata 5847 → RFC 2473 §7.2(b) ignores the DF bit) — goes to
    `encap_fragment_outer` (see below) to be encapsulated whole and outer-IPv6-fragmented in XDP, falling
    back to an `XDP_PASS` toward the kernel's companion `ip6tnl` (`STAT_ENCAP_FRAG_SLOW`, which then
    fragments the *inner* IPv4 — reachability only; see `internal/slowpath`) for the cases the fragmenter
    can't take. An in-MTU packet is instead wrapped in an outer
    Ethernet+IPv6(nexthdr=`IPPROTO_IPIP`) header and redirects it out the WAN ifindex via the `tx_ports`
    `DEVMAP_HASH`. A TCP SYN gets its advertised MSS clamped (`clamp_tcp_mss`) on the way past, *before* the
    fragmentation branch — a SYN is never itself oversized, and clamping it is what keeps the rest of that
    connection out of the fragmenter. Native IPv6 arriving here (a LAN client's IPv6 transit traffic) is
    *not* IPv4, so instead of being encapsulated it takes the native-IPv6 forwarding fastpath
    (`handle_ipv6_forward`, see below).
  - `encap_fragment_outer` + `emit_softwire_fragment`/`xdp_softwire_frag0..3` (`SEC("xdp")`) — in-XDP
    softwire fragmentation (RFC 6333 §5.3). XDP emits exactly one frame per input frame, so the fragments
    are made by cloning: `encap_fragment_outer` encapsulates the oversized inner IPv4 once behind outer
    Ethernet + IPv6 (`nexthdr = IPPROTO_FRAGMENT`) + a Fragment header (offset 0, M=1, one
    `bpf_get_prandom_u32()` ID every clone then inherits — no metadata passing needed), decrements the
    inner TTL, and `bpf_redirect_map`s it to the `frag_ports` `DEVMAP` with `BPF_F_BROADCAST` (one clone
    per possible fragment, `MAX_SOFTWIRE_FRAGS` = 4). Entry *i* targets the A end (`mm-frag<i>`) of a
    dedicated large-MTU companion veth pair (`internal/fragpath`), whose B end (`mm-frag<i>p`) runs
    `xdp_softwire_frag<i>` as its rx XDP program: it trims the clone to fragment *i* (adjust head/tail,
    rewrite `payload_len`/`frag_off`/M from stack-copied headers) and redirects it out the WAN, or drops
    it when the packet needed fewer fragments. One *device* per fragment index is load-bearing twice over
    (documented on `frag_ports`): the kernel's devmap enqueue validates the untrimmed clone's length
    against the target device's MTU before any program could trim it (`is_valid_dst` → `xdp_ok_fwd_dev`),
    so the target can never be the WAN itself; and enqueued frames are batched per target device with only
    the batch's *first* devmap egress program run over all of them, so per-entry `bpf_devmap_val` programs
    on one shared device cannot express per-fragment behavior (both discovered empirically — the second
    produced four identical fragment-0s). Counted per packet (`STAT_ENCAP_FRAG_XDP`) and per fragment
    (`STAT_ENCAP_FRAG_SEG`). The FIB lookup for the fragments' L2 asks for a *fragment-sized* `tot_len` —
    `bpf_fib_lookup` returns `FRAG_NEEDED` *before* filling `ifindex`/macs when `tot_len` exceeds the
    route MTU, so asking with the full oversized length would echo the ingress ifindex back and trip the
    wrong-interface check. Guards fall back to the ip6tnl (`STAT_ENCAP_FRAG_SLOW`): `frag_unit` unset,
    inner > 4×`frag_unit` or > `frag_max_inner` (the veth pairs' clone-admission ceiling), device MTU
    shrunk below the configured unit, `frag_ports` unpopulated, expiring TTL (kernel answers Time
    Exceeded), or an unresolvable WAN next hop.
  - `xdp_dslite_decap` (`SEC("xdp")`, attach to the WAN interface) / `xdp_dslite_decap_cpu` (`SEC("xdp/cpumap")`
    second-stage variant): validates the outer IPv6 header matches the configured AFTR/B4 pair
    (`is_expected_dslite_peer`), optionally fans decap work out across CPUs first
    (`maybe_redirect_to_cpu` + the `cpu_map`/`fanout_*` maps, gated by `fanout_config.enabled`), strips the
    IPv6 header, resolves the LAN egress interface via `bpf_fib_lookup`, and — if the egress path MTU is too
    small — replies with an ICMPv4 Fragmentation-Needed re-encapsulated back through the softwire for a DF
    inner packet (`send_dslite_icmp_frag_needed`, since the original IPv4 sender is only reachable via the
    AFTR), or `XDP_PASS`es the still-encapsulated non-DF packet to the companion ip6tnl to decap and
    IPv4-fragment toward the LAN (`STAT_DECAP_FRAG_SLOW`). A TCP SYN is MSS-clamped here too
    (`clamp_tcp_mss`), on the still-encapsulated packet so the slow paths get it as well — the *encap*
    direction is what that clamp protects, since the SYN-ACK arriving from the AFTR announces what the
    remote will receive and so bounds what the LAN client sends into the softwire. An inner packet whose TTL expires here is
    answered the same way, with a softwire-encapsulated ICMPv4 Time Exceeded
    (`send_dslite_icmp_time_exceeded`, `STAT_ICMP_TIME_EXCEEDED`, RFC 1812 §5.3.1). Both of these ICMPv4
    errors are sourced from the well-known B4 address `192.0.0.2` (RFC 6333 §5.7 / RFC 7335), are
    `redirect`ed out `b4_config.wan_ifindex` rather than `XDP_TX`ed (so they also work from the cpumap
    variant, where `XDP_TX` isn't available), and go through `icmp_error_eligible` — RFC 1812 §4.3.2.7's
    "never answer a non-initial fragment, another ICMP error, or a non-unicast source". The Time Exceeded
    decision deliberately sits *after* the LAN FIB lookup, not on arrival: `BPF_FIB_LKUP_RET_NOT_FWDED`
    means the packet is addressed to the CPE itself, where TTL 1 is legal and must be delivered locally,
    and every case the in-place rewrite can't express (an offending packet shorter than the 110-byte
    reply, IPv4 options) is `XDP_PASS`ed so the ip6tnl and the kernel's own forwarding originate the error
    instead of the datapath dropping it. A *fragmented* softwire packet (outer
    `nexthdr == IPPROTO_FRAGMENT`, matched to a peer) is `XDP_PASS`ed up front for kernel reassembly +
    ip6tnl decap (`STAT_DECAP_REASM_PASS`), since XDP can't reassemble. Native
    (non-softwire) IPv6 arriving on the WAN — the `outer_iph->nexthdr != IPPROTO_IPIP` case, previously
    `XDP_PASS`ed to the kernel — takes the same native-IPv6 forwarding fastpath instead.
  - `handle_tunnel_icmpv6` (called from `xdp_dslite_decap` before the native-IPv6 branch) — the RFC 2473
    §8 tunnel ICMP relay. An inbound ICMPv6 error is claimed only when its quote is one of *this* B4's own
    softwire packets (`find_dslite_local_slot`: quoted saddr/daddr match a `next_hops` slot's B4/AFTR pair
    *and* the error is addressed to that same B4) and the quoted inner IPv4 resolves to a managed LAN
    interface — together the spoof check, since believing a fabricated quote would let anyone on the IPv6
    internet inject ICMPv4 errors into the LAN or shrink the softwire MTU. It then rewrites the frame in
    place (trim to `ICMPV4_ERROR_FRAME_LEN`, `write_lan_icmpv4_error`) into an untunneled ICMPv4 error out
    the LAN — untunneled, unlike the decap path's replies above, because here the original sender *is* a
    LAN client. A Packet Too Big first records the path MTU (`learn_tunnel_pmtu` → the `tunnel_pmtus`
    map, floored at 1280 per RFC 8201 §4, aged out after 10 minutes) and is then relayed only if the quote
    had DF; a non-DF one is dropped, having been consumed. Anything not claimed falls through to the
    native-IPv6 path exactly as before (`TUNNEL_ICMP_NOT_MINE`), so an ordinary ICMPv6 packet addressed to
    the CPE still reaches the kernel — the caller re-derives its packet pointers after the call, since the
    verifier merges the `bpf_xdp_adjust_tail` path into the one that didn't touch the frame.
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
    directly reachable, unlike the decap path's softwire-encapsulated ICMPv4 replies), sourced from
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
    fallback WAN MACs, WAN ifindex, and the softwire fragmenter's `frag_unit`/`frag_max_inner`) and
    `lan_configs` (`HASH` keyed by LAN ifindex: gateway IPv4, inner MTU); the fragmenter adds the
    `frag_ports` `DEVMAP` of companion-veth ifindexes, and the tunnel ICMP relay the `tunnel_pmtus`
    `ARRAY` (per `next_hop` slot: the learned softwire path MTU + a `bpf_ktime_get_ns` stamp, written by
    the datapath and read by both encap and userspace).
    The optional IPv6 software-RSS stage adds `ipv6_rss_config_map`/`ipv6_rss_cpus`/`cpu_map_v6` (separate
    from the dormant DS-Lite `fanout_*`/`cpu_map`). Per-path counters live in the `stats` `PERCPU_ARRAY`
    (see `enum stat_id`; the field/index order in `pkg/datapath/stats.go`'s `statID` and the `Stats` struct
    must be kept in sync with it by hand — new counters are appended before `STAT_MAX`).
  - Every ICMP error the datapath originates (`send_dslite_icmp_frag_needed`,
    `send_icmpv6_pkt_too_big`) is gated by `icmp_error_allowed()`, a
    per-CPU token bucket (`icmp_error_rate` `PERCPU_ARRAY`, 100/s sustained + 20 burst per CPU) — RFC 4443
    §2.4(f) makes rate-limiting originated ICMPv6 errors a MUST, and these `XDP_TX` replies bypass the
    kernel's own `icmp_ratelimit` sysctls entirely. When the bucket is empty the offending packet is
    dropped without an error (mirroring the kernel's own behavior), counted in `STAT_ICMP_RATE_LIMITED`.
  - **Capture hooks** (`xdpcap_hook`/`xdpcap_hook_cpu` + `xdpcap_exit`) — ABI-compatible with
    [cloudflare/xdpcap](https://github.com/cloudflare/xdpcap), because almost nothing this datapath does
    is visible to tcpdump: XDP_REDIRECT and XDP_DROP never reach the AF_PACKET tap, and encap, decap, the
    fragmenter's clones and the cpumap stages all end in a redirect, so the stats counters say how many
    packets took each path but never which ones. A hook is a `PROG_ARRAY` indexed by XDP action that each
    entry program tail-calls on its way out; empty while nothing is capturing, so the tail call misses and
    the entry program's own return value stands (cost: one prog-array lookup per packet). Every entry
    program is therefore a thin wrapper (`xdp_dslite_encap` → `do_xdp_dslite_encap`, and so on for decap,
    both cpumap stages and the `SOFTWIRE_FRAG_PROG` macro) around an `__always_inline` body, so one hook
    covers its dozens of returns. The arrays are pinned by `pkg/datapath/pin.go`, the same out-of-band
    route the stats map takes. Two arrays, not one: the kernel's prog-array compatibility check requires a
    program's `expected_attach_type` to match the array owner's, so the cpumap-attached stages get their
    own (`xdpcap_hook_cpu`) — sharing would have made the hook on the path *every* packet takes unusable
    to a plain rx-XDP filter program, to instrument two stages that are off by default. Note a hook fires
    on the way *out*, so a capture sees the packet as the datapath left it (on the encap path the finished
    outer IPv6 frame, not the inner IPv4 that arrived). `docs/operability-backlog.md` §3 has the rest,
    including why stock `xdpcap` needs a one-line patch to attach and what an in-tree
    `minuteman monitor` would need.
  - **`bpf/datapath_helpers.h`** — shared low-level helpers (checksum fold/compute, IPv4 TTL decrement with
    incremental checksum update, IPv6 hop-limit decrement (`decrease_ipv6_hoplimit` — no checksum, so
    trivial), L2(+VLAN)/IPv4/IPv6 header parsing with bounds checks, IPv6 address comparison and
    unspecified/forwardable classification (`ipv6_addr_equal`/`ipv6_addr_is_unspecified`/`ipv6_is_forwardable`),
    IPv6 flow hashing (`inner_ip6_hash`), the outer-IPv6 header writer (`write_outer_ipv6`, whose `nexthdr`
    parameter serves both the plain `IPPROTO_IPIP` encap and the fragmenter's `IPPROTO_FRAGMENT`), and ICMP
    error construction: DS-Lite-tunneled ICMPv4 Fragmentation-Needed and Time Exceeded (sharing
    `write_dslite_inner_icmp_iph`, which sources them from the RFC 6333 §5.7 well-known B4 address
    `192.0.0.2`), plus ICMPv6 Packet Too Big
    (`write_icmpv6_pkt_too_big`, whose `icmpv6_checksum` covers the IPv6 pseudo-header, unlike ICMPv4's).
    `icmp_error_eligible` is the shared RFC 1812 §4.3.2.7 gate every originated ICMPv4 error runs through
    (non-initial fragment / ICMP error / non-unicast source → don't answer), distinct from
    `icmp_error_allowed()`'s rate limiting in `datapath.bpf.c`. Also `clamp_tcp_mss` (the TCP MSS clamp both
    the encap and decap paths call) and the `csum_replace16` it needs — XDP has no `bpf_l4_csum_replace`
    (that's a `__sk_buff` helper), so an L4-covered field rewritten here fixes up the TCP checksum by hand
    (RFC 1624 eqn. 3). Its option walk is a real bounded loop, not `#pragma unroll`: clang declines to
    unroll it, and the verifier's bounded-loop support carries it since the trip count is constant and every
    packet access inside is bounds-checked.
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
    `SetB4Config` derives the softwire fragmenter's `frag_unit` from `B4Config.WANMTU` (`softwireFragUnit`
    in `frag.go`: largest multiple of 8 ≤ WAN MTU − 48) and passes `FragMaxInner` through, and resolves
    `B4Config.TCPMSSClamp` into `b4_config.mss_clamp` (`mss.go`).
  - `mss.go` — the TCP MSS clamp policy: `TCPMSSClampAuto` derives the clamp from the softwire MTU
    (`autoTCPMSSClamp`: MTU − 40 outer IPv6 − 40 option-free IPv4+TCP, per RFC 6691's rule that options
    aren't deducted; below `minTCPMSSClamp` = 536 it disables itself rather than push peers under RFC 1122
    §4.2.2.6's floor), a positive value pins it, zero disables it. `resolveMSSClamp` records which of those
    the caller chose on the `Loader`, so `SetSoftwireMTU` knows whether a newly learned path MTU may move
    it. Deliberately derived in Go rather than from encap's own per-packet effective MTU, even though encap
    has that figure: an MSS only affects connections that haven't sent their SYN yet, so a poll interval of
    lag costs nothing, and one value keeps both directions clamping alike — the decap side has no local MTU
    to derive one from.
  - `frag.go` — `EnableSoftwireFrag(redirectIfindexes, fwdIfaces)` wires the in-XDP softwire fragmenter to
    the companion veth pairs `internal/fragpath` created: attaches `xdp_softwire_frag<i>` to pair *i*'s B
    end (which also activates the pair's NAPI), then points `frag_ports[i]` at the pair's A end —
    attach-then-populate, so the datapath (whose `encap_fragment_outer` guard checks `frag_ports`
    resolves) never broadcasts into a pair with no consumer. `MaxSoftwireFrags` (4) mirrors the C
    `MAX_SOFTWIRE_FRAGS` and is what `fragpath.NumPairs` is defined from.
  - `pmtu.go` — `TunnelPMTU()` reads the smallest not-yet-aged-out softwire path MTU across the
    `tunnel_pmtus` slots (aged on the same `CLOCK_MONOTONIC` the datapath stamps with, `TunnelPMTUExpiry`
    mirroring the C `TUNNEL_PMTU_EXPIRY_NS`), and `SetSoftwireMTU(mtu)` re-derives `b4_config.frag_unit`
    from it (plus `mss_clamp`, when the clamp is automatic) — the only fields of `b4_config` written after
    startup, and the reason the `frag_unit` derivation lives in Go rather than in the datapath (see the
    `handle_tunnel_icmpv6` bullet).
  - `ipv6_rss.go` — `EnableIPv6SoftwareRSS([]uint32)` turns on the native-IPv6 software-RSS cpumap stage
    across the given CPU ids: it populates `cpu_map_v6` with `bpfBpfCpumapVal{Qsize, prog: XdpIpv6FwdCpu.FD()}`
    per CPU, fills `ipv6_rss_cpus` (slot → cpu), and sets `ipv6_rss_config{Enabled, CpuCount}`. Off unless
    called (`-ipv6-sw-rss`). `cilium/ebpf` v0.21 has no high-level CPUMAP-with-program value helper, so the
    raw `bpf_cpumap_val` struct bpf2go generated (`bpfBpfCpumapVal`) is `Put` directly.
  - `stats.go` — `Stats()` sums the `PERCPU_ARRAY` counters across CPUs into a plain `Stats` struct (the
    summing is factored as `sumStats(*ebpf.Map)` so it also runs against a bare map handle). The
    field/index order (`statID` in `stats.go`) must be kept manually in sync with `enum stat_id` in the C
    source — bpf2go can't export a Go enum here because `enum stat_id` never appears as a stored map value
    type in the BTF (only as inlined integer constants), so `-type stat_id` finds nothing.
  - `pin.go` — `Load()` pins to bpffs the maps an out-of-band observer reaches minuteman through
    (`pinMaps`, all under `/sys/fs/bpf/minuteman/`): `stats`, so counters stay readable while minuteman
    runs (`minuteman stats [--json]` via `ReadPinnedStats()` in `stats.go`, or `bpftool map dump
    pinned ...`), and the two `xdpcap_hook`/`xdpcap_hook_cpu` capture hooks, so a packet capture can be
    installed into the running datapath (see the hook bullet under `bpf/datapath.bpf.c` above). A stale
    pin from a crashed previous run is removed first (unpin-then-repin, `internal/slowpath`'s
    stale-device stance), pin failure is fail-fast with a
    bpffs-mount hint, and `Loader.Close` unpins best-effort. Nothing else is pinned. NB for anything
    that runs minuteman inside a netns: `ip netns exec` creates a new mount namespace and remounts
    `/sys`, stranding the pin on a private bpffs — enter with `nsenter --net=...` instead (the netns rig
    does; see `test/netns/README.md`'s "Reading datapath stats").
  - `xdproles.go` — `XDPRoles(progIDs)` classifies the XDP program ids a link dump reported
    (`pkg/netlink.Socket.Links`), returning an entry only for the ones belonging to the *running*
    instance and labelling each `wan`/`lan`/`frag`; it's what lets `minuteman stats interfaces` name the
    datapath's interfaces without the daemon publishing a list. Membership is decided by the program
    referencing the same map the bpffs pin points at (`pinnedStatsMapID` + `ProgramInfo.MapIDs`), *not*
    by its name: a name is not unique — an unrelated XDP program can share one, so can a stale second
    minuteman whose pin was already replaced — whereas a map id is unique per loaded map, and every
    interface-attached program bumps a stats counter so none is missed. The name is used only for the
    role label, comparing both sides truncated to `BPF_OBJ_NAME_LEN-1` (15) because the kernel's name
    field is that wide and `cilium/ebpf` un-truncates from BTF func info only when the object carries
    it — so `xdp_dslite_encap` arrives whole or as `xdp_dslite_enca` depending on the build, and
    truncating both sides classifies either identically. A program id that can't be opened or inspected
    is treated as not ours rather than as an error (the dump is a snapshot; a device can lose its
    program in between).
  - IPv4/IPv6 addresses are exchanged with the BPF maps as `netip.Addr` at the API boundary; internally they're
    converted to the `in6_u.u6_addr8`/big-endian-`uint32` layouts the generated `bpfB4Config`/`bpfLanConfig`
    structs expect (see `config.go`).
- **`pkg/dhcpv6/`** — generic, stdlib-only DHCPv6 client covering both RFC 3736 stateless service and the
  RFC 3315 stateful exchanges a PD client needs. `duid.go` (DUID-LL from a MAC — regenerated fresh each run
  rather than persisted, since it's a pure function of hardware-type+MAC), `message.go`/`options.go` (wire
  codec; option *codes* for options a consuming package decodes itself, e.g. `OptionIAPD`/`OptionIAPrefix`/
  `OptionAFTRName`, live here as bare constants, but their actual decoding does not — the exception being
  options that are generic DHCPv6 *and* have more than one consumer here, which get an `Options` accessor
  instead of being decoded once per consumer: `InformationRefreshTime()` (RFC 4242) and `DNSServers()`
  (RFC 3646, read by both `pkg/aftrdiscovery` and `pkg/prefixdelegation`)), `retransmit.go` (pure
  RFC 3315 §5.5/§14 timing for every exchange — initial jitter via `InitialDelay`, then backoff capped at each
  exchange's MRT with jitter re-applied around the cap forever, *not* clamped to a fixed value; Request/
  Release additionally have a maximum retransmission *count*; the formulas draw from a `*rand.Rand` they're
  given), `exchange.go` (`Exchange` -- type, options, expected reply type, `Timing` -- with `Message` to build
  what's sent and `Answers`, RFC 3315's general validation rule on top of the type/XID match; and the
  `Exchanger` interface that runs one: the package holds no socket), plus the exported stateful exchanges `Solicit`/`Request`/`Renew`/`Rebind`/`Release` — all
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
  DUID-LL. `Lease` also carries the Reply's `DNSServers` (RFC 3646), requested via the `requestedOptions`
  ORO every exchange in this package sends: nothing to do with the delegation itself, but on a network
  that doesn't answer Information-Request this stateful exchange is the *only* DHCPv6 source of a
  resolver, and `cmd/minuteman`'s HB46PP fallback needs one — a renewal takes its servers from its own
  Reply rather than inheriting the previous lease's, since the ORO went out with it too, so silence is
  the server declining rather than the question going unasked. `acquire.go`'s `Acquire()` drives the full
  Solicit→Advertise→Request→Reply exchange (blocks,
  retrying, until it succeeds or ctx is cancelled — same rationale as `aftrdiscovery.Discover`).
  `maintain.go`'s `Maintain()` is the part `aftrdiscovery` deliberately leaves as future work for its own
  refresh interval: a lease that's never renewed actually expires and breaks LAN connectivity, so this
  drives RFC 3315's full renewal ladder (Renew at T1 → Rebind at T2 on failure → fresh `Acquire` on failure)
  indefinitely, calling back into the caller on every change, and sends a best-effort `Release` on shutdown.
  The T1/T2 that ladder runs on are not necessarily the server's: `timers.go`'s `effectiveTimers` resolves
  a delegated 0 — RFC 9915 §21.21's way of leaving the renewal timing to the requesting router, which
  §14.2 then requires to choose times that avoid message storms and in particular *not* transmit
  immediately — into §21.21's own recommended 0.5 × / 0.8 × of the shortest preferred lifetime, floored by
  `minDerivedT1` (1 minute, §14.1's rate-limiting MUST expressed as a cadence), capped by the shortest
  *valid* lifetime (a Renew scheduled past the binding's own death can only fail into a full re-Acquire —
  more messages than renewing in time, so the ceiling serves the same anti-storm purpose as the floor)
  and clamped to keep
  T1 ≤ T2 whichever of the two the server did pin; a non-zero server value is used verbatim, since §21.21
  makes that a MUST, and `usableIAPD` discards an IA_PD carrying the T1 > T2 > 0 combination §21.21 calls
  invalid (plus, per §21.22, any individual prefix whose preferred lifetime exceeds its valid one). Taken literally instead, T1=0 renewed on every exchange RTT — a storm against any server that
  sends it (the netns rig's `MM_PD_ZERO_TIMERS=1` mode is the regression test). Outgoing IA_PDs zero
  their own T1/T2 (§21.21's client-side SHOULD; the server ignores them anyway).
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
  locally, the same rationale as `bpf/uapi/linux/*.h`). `advertise.go`'s `Serve(ctx, iface, cfg, updates)`
  is the
  actual RFC 4861 §6.2/§10 timing — a fast initial burst of RAs, settling into a jittered periodic
  cadence, plus rate-limited replies to inbound Router Solicitations — ending with a best-effort final
  `RouterLifetime=0` RA when `ctx` is cancelled (§6.2.5's graceful-shutdown signal), mirroring
  `prefixdelegation.Maintain`'s blocks-until-cancelled shape. `updates` (an `*Updater`, nil for a
  never-changing config) is how a caller replaces `cfg` *without* restarting the goroutine: a size-1
  latest-wins channel of `Config`s, each applied in place and — if it differs from the current one —
  advertised promptly rather than at the next scheduled RA, subject to §6.2.4's `MIN_DELAY_BETWEEN_RAS`
  floor. It exists because cancel-then-restart is not a neutral way to change what's advertised:
  cancellation is the *shutdown* path above, so a restart tells every LAN client the router (and, since
  the RDNSS option's lifetime tracks `RouterLifetime`, its DNS server) is going away moments before the
  replacement worker re-announces both — a flap `internal/lanprefix` used to inflict on every DHCPv6-PD
  Renew. A send failing with `EADDRNOTAVAIL` is
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
  package that builds/parses netlink wire messages, used by `internal/lanprefix` (address assignment),
  `internal/wanextend` (WAN-prefix discovery, host routes), `internal/slowpath` (the companion ip6tnl) and
  `internal/fragpath` (the fragmenter's companion veth pairs)
  — split out from `internal/lanprefix`'s
  original private implementation once `internal/wanextend` needed the same mechanism. `message.go` builds
  `RTM_NEWADDR`/`RTM_DELADDR`/`RTM_GETADDR`/`RTM_NEWROUTE`/`RTM_DELROUTE` and `RTM_NEWLINK`/`RTM_DELLINK`
  requests and parses responses —
  `walkMessages` splits a single `Recvfrom` buffer into individual messages (a dump response packs several
  together), `parseIfAddrMsg` decodes an `RTM_NEWADDR` dump entry's `IFA_ADDRESS`/`IFA_LOCAL` attributes,
  filtering to global scope (`RT_SCOPE_UNIVERSE`) since WAN-prefix discovery has no use for the WAN's own
  link-local address. `encodeNestedAttr` is the container-attribute primitive (a plain `encodeRtAttr` over
  concatenated already-encoded children, since every attribute is 4-byte-aligned) the `IFLA_LINKINFO`/
  `IFLA_INFO_DATA` nesting needs; `buildAddIP6TnlMessage`/`buildChangeIP6TnlMessage`/`buildSetLinkUpMessage`/
  `buildDelLinkMessage` build the ip6tnl create/changelink/up/delete requests (with locally-`#define`d
  `IFLA_IPTUN_*` codes and the `IP6_TNL_F_IGN_ENCAP_LIMIT` flag, since `x/sys/unix` doesn't export them —
  same vendoring rationale as `pkg/routeradvert`'s `ICMP6_FILTER`), and `buildAddVethMessage` the veth-pair
  create request (the peer described by its own `ifinfomsg` nested in `VETH_INFO_PEER`, vendored the same
  way). `socket.go`'s `Socket` is the actual
  send/receive I/O: `AddAddr`/`DelAddr` (`NLM_F_
  REPLACE` makes `AddAddr` idempotent), `Addrs` (an `RTM_GETADDR` dump, looping `Recvfrom` until
  `NLMSG_DONE`), `AddRoute`/`DelRoute` (a directly-attached route — `RTA_OIF` only, no `RTA_GATEWAY`, scope
  `RT_SCOPE_LINK` — matching `ip route add <dst> dev <iface>`; family follows the prefix, so the same call
  serves `internal/wanextend`'s IPv6 `/128` host routes and `internal/slowpath`'s IPv4 default route, and a
  `/0` prefix omits `RTA_DST`; `AddRoute` is `NLM_F_REPLACE`-idempotent too), and
  `AddIP6Tnl`/`SetIP6TnlEndpoints`/`AddVeth`/`SetLinkUp`/`SetLinkMTU`/`DelLink` for the companion device
  lifecycles (`SetLinkMTU` exists for the ip6tnl's MTU, which has to follow a learned softwire path MTU or
  the fallback keeps fragmenting to a size the path drops). `Links` is the one read-only link operation
  (`buildGetLinkMessage`/`parseIfInfoMsg`/`parseXDPProgID`): an `RTM_GETLINK` dump giving each device's
  index, name and attached XDP program id (`IFLA_XDP` → `IFLA_XDP_PROG_ID` — the id for whatever attach
  mode is in use, where the per-mode `IFLA_XDP_*_PROG_ID` attributes only report *which* mode), which is
  how `minuteman stats interfaces` finds the datapath's interfaces without the daemon publishing them. It
  reads into a 64 KiB buffer rather than `Addrs`' single page: a link dump entry carries the device's
  whole `rtnl_link_stats64` plus per-protocol attributes, and a `Recvfrom` buffer shorter than the
  kernel's next dump message silently truncates it.
- **`internal/dnsproxy/`** — the DNS proxy RFC 6333 recommends a DS-Lite B4 run (the B4 SHOULD act as a DNS
  proxy for LAN clients): opaque byte-relay only, no DNS message parsing, caching, or rewriting of any
  kind. A molecule supervision tree (`Spec(Config)`, one_for_one): per listen address, a UDP listener and a
  `gentcpacceptor` raw TCP listener, each bound before the tree's start returns (so `cmd/minuteman` fails
  fast, and only advertises one of these addresses as an RDNSS DNS server once it's actually bound — see
  `startDNSProxy`/`routeradvert`). The UDP listener (`udp.go`, a proc process: it starts a process per
  query) owns a `genudp` socket in `N(maxInFlight)` mode and re-arms it by one as each forwarder exits, so
  queries in flight are bounded and the rest wait in the kernel; it waits out a link-local address still
  DAD-tentative (`EADDRNOTAVAIL`, `bindRetries`) before its TCP sibling binds. Each forwarder tries
  `Config.Upstreams` in order over a fresh one-shot `genudp` socket (deliberately not pooled: a dedicated
  socket means a response can never be confused with a different concurrent query's), bounded by
  `udpQueryTimeout`; every upstream failing just drops the query, relying on the client's own resolver to
  retry. `tcp.go`'s `relay` is a full bidirectional byte-level `io.Copy` relay per accepted connection rather
  than framing individual length-prefixed DNS-over-TCP messages — RFC 7766 §6.2.1 allows pipelining
  multiple queries on one connection, which a byte relay handles for free. A listen address that's IPv6
  link-local carries its zone (`routeradvert.LinkLocalAddr`) so the kernel binds the right interface.
  Tested with `go test` against loopback upstreams, and end to end by the netns rig's `MM_DNS_PROXY=1`.
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
- **`pkg/ethtool/`** — minimal hand-rolled `SIOCETHTOOL` client reading exactly one thing: a device's
  driver-specific statistics, i.e. what `ethtool -S <iface>` prints, for `minuteman stats interfaces`. Three
  ioctls in the sequence `ethtool(8)` itself uses — `ETHTOOL_GSSET_INFO` (how many `ETH_SS_STATS`
  counters), `ETHTOOL_GSTRINGS` (their names, fixed 32-byte NUL-padded fields), `ETHTOOL_GSTATS` (their
  `__u64` values) — with the `ifreq`+`ifr_data` layout and the constants `x/sys/unix` doesn't export
  (`ETH_SS_STATS`, `ETH_GSTRING_LEN`) vendored locally, same rationale as `pkg/netlink`'s `IFLA_IPTUN_*`.
  Two non-obvious details: request buffers come from `alignedBuf` (allocating `[]uint64` and viewing it
  as bytes) because `struct ethtool_stats`' trailing `__u64` array needs 8-byte alignment that
  `make([]byte, n)` doesn't promise; and "no statistics" is not always an errno — the kernel *clears*
  `sset_mask`'s bit for a string set the driver doesn't implement and returns success, while older
  drivers return `EOPNOTSUPP`/`EINVAL`, so all three become the `ErrNotSupported` sentinel a caller can
  report per interface without failing the others. Returns a slice, not a map, to preserve the driver's
  own grouping (per queue, per XDP action) that alphabetising would scatter. The newer ethtool *netlink*
  interface is **not an alternative** here, despite looking like the modern one: its own documentation
  says `ETHTOOL_MSG_STATS_GET` "is not a re-implementation of `ETHTOOL_GSTATS` which exposed
  driver-defined stats" — it returns the standardised `eth-phy`/`eth-mac`/`eth-ctrl`/`rmon`/`phy`
  groups, while the driver-defined set (where every `xdp_packets`/`xdp_redirect`/`xdp_drops` counter
  lives) has no netlink equivalent and `ethtool -S` itself still uses these ioctls for it. Those
  standard groups could be *added* later — they'd need a generic-netlink client `pkg/netlink`
  (`NETLINK_ROUTE` only) doesn't have, and a veth exposes none of them, so the netns rig couldn't cover
  it. No unit tests — pure syscall wrappers, exercised by the netns rig like
  `pkg/ndproxy`'s and `pkg/routeradvert`'s socket I/O.
- **`cmd/minuteman/main.go`** — thin CLI entrypoint. Flags: `-wan`, `-b4` (optional — omitted means the
  softwire source is tracked dynamically; see `resolveB4`/`internal/softwirectl` below), `-aftr`
  (optional — see below),
  repeatable `-lan iface=gatewayIP[/prefixlen][,mtu]` (the `/prefixlen`, default `/24`, is the DHCPv4
  subnet), `-wan-dst-mac` (fallback only), `-stats-interval`, `-dhcpv6-pd`
  (opt-in prefix delegation), `-ndproxy` (opt-in RFC 4389 proxying, mutually exclusive with `-dhcpv6-pd` —
  validated in `run()` before anything else happens), `-dns-proxy` (opt-in DNS proxy, orthogonal to both
  IPv6-provisioning flags) with repeatable `-dns-server` to override its upstreams, `-dhcpv4` (opt-in DHCPv4
  server, orthogonal to everything else) with `-dhcpv4-lease` and repeatable `-dhcpv4-dns`,
  `-tcp-mss-clamp` (`auto` by default — track the softwire MTU; `off`, or an explicit MSS in bytes; parsed
  by `internal/cliconfig.ParseMSSClamp` into the `datapath.B4Config.TCPMSSClamp` policy),
  `-ipv6-sw-rss` (opt-in native-IPv6 software-RSS cpumap fanout — off by default, for NICs whose hardware
  RSS can't spread flows; when set, `run()` calls `dp.EnableIPv6SoftwareRSS(onlineCPUs())` after WAN/LAN
  attach, once every egress ifindex is registered in `tx_ports`),
  `-hb46pp-vendor-id`/`-hb46pp-product`/`-hb46pp-version`
  (HB46PP client-identity query parameters — see below; default to the documentation OUI `acde48` since
  minuteman has no IEEE OUI, overridable since a VNE may key rollout/workaround decisions off them, not just
  statistics), and `-pidfile` (written only after every fail-fast startup step, so its existence means
  "up", removed on graceful exit — for a supervisor or the test rig; see also
  `docs/minuteman.service.example`, the systemd way to run minuteman in production). Flag-value
  parsing (`LANSpec`/`LANSpecList`, `AddrList`, MAC parsing) lives in `internal/cliconfig`, not in `main.go` itself.
  Besides the default flag-driven run, `main()` dispatches to a **cobra** command tree
  (`stats.go`'s `newRootCmd`) whenever the first argument isn't a flag — before `flag.Parse`, so the
  flag-only invocation stays the daemon and only the subcommands are cobra's (the daemon's own flags
  are still the stdlib `flag` package's, deliberately: converting them would break every `-wan`-style
  invocation, since pflag reads a single dash as a shorthand cluster). The tree's root carries no
  `Run`; it exists to give subcommands their `minuteman <cmd>` usage paths and to reject a mistyped
  one with a suggestion. Its default `completion` command is disabled — the daemon half isn't in the
  tree, so a generated script would silently complete nothing for it. Because the two halves parse
  flags differently, `normalizeLegacyArgs` rewrites Go-flag-style single-dash long options into
  pflag's double-dash form before `Execute` (`-json` → `--json`, stopping at `--`, never touching a
  one-character shorthand like `-h`): without it one command line would carry two incompatible
  conventions, and `stats -json` would fail with pflag's "unknown shorthand flag: 'j'".
  `minuteman stats [--json]` (`stats.go`'s `runStats`) prints the datapath counters of the
  *running* instance from the bpffs-pinned stats map via `datapath.ReadPinnedStats` — text as
  `Name: value` lines (shell-friendly), `--json` as the `Stats` struct (`jq .DecapMartian`); needs the
  same root/CAP_BPF the daemon needs. `minuteman stats interfaces` (aliases `iface`/`ifaces`;
  `ifstats.go`'s `collectInterfaceStats`) reports each
  XDP-bound interface's driver counters — the `ethtool -S` set, read via `pkg/ethtool` — labelled
  `wan`/`lan`/`frag`, which is what tells apart "the datapath didn't handle it" from "the packet never
  arrived" (and makes the fragmenter's clone-and-trim visible per companion veth: `xdp_redirect` on the
  pairs a packet needed, `xdp_drops` on the ones it didn't). The interface list is derived from the
  *kernel*, not from the daemon or from `-wan`/`-lan`: `pkg/netlink.Socket.Links` (an `RTM_GETLINK`
  dump) reports each device's attached XDP program id and `datapath.XDPRoles` says which of those ids
  belong to this instance — by the program *referencing the pinned stats map*, not by name, since a
  name is not unique but a map id is. So the list can't drift from what's really attached, covers the
  companion veths no flag names, and needs nothing published beyond the pin — but `stats interfaces`
  must run in the datapath's own netns to see the interfaces (the pin itself is on the host bpffs; see
  `pkg/datapath/pin.go`'s `nsenter --net` note). Being a subcommand rather than a flag on `stats` is
  what keeps each view's JSON directly walkable: `stats --json` is the `Stats` struct itself,
  `stats interfaces --json` the per-interface array (`jq '.[0].Stats.xdp_packets'`). `--json` is
  declared once, persistently, on `stats`, and inherited. The flag this subcommand replaced survives
  as a hidden, deprecated `stats --iface`, printing exactly what it used to (counters, then
  interfaces; under `--json` the one object with `Interfaces` embedded, `legacyStatsOutput`) so a
  script written against it isn't silently handed a different shape.
  Startup order is load-bearing in one place: when `-dhcpv6-pd` is set, `run()` calls
  `prefixdelegation.Acquire` **before** `resolveAFTR`, and hands the lease's DNS servers (via
  `pdDNSServers`) to AFTR discovery, to `startSoftwireControl` (re-discovery), and — as a last fallback behind
  `-dns-server` and the discovery-learned set — to `-dns-proxy`'s upstreams. The rest of the PD setup
  (LAN address assignment, RA workers, `Maintain`) still runs in its old position, with `runPrefixDelegation`
  now taking the already-acquired lease. Both exchanges go through the WAN's one DHCPv6 client
  (`internal/dhcpv6client`), which runs them one at a time, so only their order changed, not their concurrency.
  `resolveAFTR()` returns `-aftr` parsed directly if given (in which case its second return, the DNS
  servers `-dns-proxy` defaults to using, is nil — that path skips the DHCPv6 exchange entirely), otherwise
  blocks on `pkg/aftrdiscovery.Discover`
  using the same lifecycle context as `SIGINT`/`SIGTERM` handling, bounding only the Information-Request
  phase at `informationRequestTimeout` (the AFTR-name DNS resolution that follows is not bounded, so a
  timeout unambiguously means "nothing answered"). It falls back to `hb46pp.Discover` (capability `dslite`
  only, client identity from the three `-hb46pp-*` flags bundled into an `hb46ppIdentity`) on either
  `aftrdiscovery.ErrNoAFTRName` — DNS servers from the partial DHCPv6 result — or
  `aftrdiscovery.ErrNoReply`, where there is no partial result at all and the DNS servers are the
  PD lease's. It loops the whole DHCPv6→HB46PP chain with `retryDelayFor`-paced sleeps on HB46PP
  failure — same block-until-success-or-ctx-cancel stance, at the spec's backoff cadence so a real
  VNE's provisioning server isn't hammered, except that a failure reached *through* `ErrNoReply` is capped
  at `noReplyRetryCap` (5min): `hb46pp.RetryDelay`'s hours-long `ErrNotProvisioned` verdict would there
  have been reached without any evidence from DHCPv6 about what kind of network this is. The B4 softwire source is `-b4` if given, else resolved
  dynamically by `resolveB4()` — a `pkg/netlink.Socket.SourceForDest` (`RTM_GETROUTE`/`RTA_PREFSRC`) query
  run after `AttachWAN`, retrying until the WAN's RA-learned route to the AFTR is back, so the kernel's
  RFC 6724 logic picks the exact source its own ip6tnl would. `startSoftwireControl()` (`softwire.go`,
  started whenever the AFTR *or* the B4 is dynamic) starts the molecule supervision tree of
  `internal/softwirectl`, whose `Controller` — a pure genstatem — is the *single owner* of the live
  softwire endpoints: it runs periodic AFTR re-discovery (applying a changed AFTR via the
  flow-preserving migration, phases Priming → Draining) and, for a dynamic B4, polls the WAN source every
  30s and on a change hard-switches (`dp.SwitchAFTR`, since a B4 change can't be drained: RFC 7785 §4
  recommends the AFTR migrate its NAT state to the new B4, but that can't be relied on, so minuteman cuts
  cleanly) then re-triggers AFTR discovery. A switch can happen in any phase, so a WAN change interrupts
  even a multi-hour drain; it bumps a generation that makes every response still in flight stale. The
  datapath, tunnel and netlink calls are made by the tree's `softwire` server, discovery by its
  `aftr-discovery` process; see `internal/softwirectl/README.md`. `watchTunnelPMTU()` (always started, `pmtu.go`) polls the path MTU the datapath learns from inbound
  ICMPv6 Packet Too Big messages and applies it to the two things userspace owns — the fragmenter's
  `frag_unit` and the companion ip6tnl's MTU — including the widening direction, since a reading that ages
  out simply stops being reported. When `-dhcpv6-pd` is set, `runPrefixDelegation()` similarly blocks
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
  shutdown-draining reason. If `-dns-proxy` is set, `startDNSProxy()` starts `internal/dnsproxy`'s
  supervision tree (its start returns once every listener is bound, so a bind failure fails `run()`) listening on every `-lan`
  interface's IPv4 gateway IP *and* its own link-local IPv6 address, forwarding to `-dns-server` if any
  were given or else the DNS servers `resolveAFTR()` returned; `run()` fails fast before any of this if
  `-dns-proxy` is set but no DNS servers are available from either source. It's started *before*
  `runPrefixDelegation`/`runNDProxy` and returns the map of `-lan` interface → the link-local address it
  actually bound; that map is passed to those two so their RA workers advertise an RFC 8106 RDNSS option
  (RFC 7084 §L-11, so an IPv6-only SLAAC client gets a DNS server) pointing *only* at addresses this proxy
  really bound — never a DNS server nothing answers on. A LAN link-local still DAD-tentative at bind time
  (`EADDRNOTAVAIL`) is waited out by the UDP listener; any other bind error (port 53 in use, etc.) fails
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
  like `-dns-server`/`-dhcpv4-dns`, `ParseMAC`, `ParseMSSClamp` for `-tcp-mss-clamp`'s
  `auto`/`off`/explicit-MSS values) into typed values for `main.go` to hand to `pkg/datapath`. Thin
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
  distinct per LAN interface): `Sync()` pushes each interface's new `Config` into its already-running
  worker via `routeradvert.Updater` (starting one only where none runs yet, or where a previous one died
  of a socket error), since a Renew resets the lifetimes even when the subnet itself doesn't change and a
  long-running `Serve` goroutine has no other way to pick that up. It used to cancel-and-restart the
  worker for that, which is *not* the cheap operation the old comment here claimed: cancellation is
  `Serve`'s shutdown path, so every Renew flapped each LAN client's default route and RDNSS server via a
  `RouterLifetime=0` RA (the resolved §1 of `docs/rfc-compliance-backlog.md`).
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
  a single `netip.Prefix` rather than a per-interface list; like `RAManager.Sync` it updates each running
  worker in place through a `routeradvert.Updater` rather than restarting it — the final
  `RouterLifetime=0` RA a restart emits never deprecated the outgoing prefix anyway (that PIO still
  carries its lifetimes intact), so restarting only cost LAN clients their default route and RDNSS server
  for the length of the changeover. `hostroutes.go`'s
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
- **`internal/slowpath`** — owns the kernel companion `ip6tnl` that gives the datapath softwire
  *reassembly* (RFC 6333 §5.3's inbound half) plus the *fallback* for what the in-XDP fragmenter can't
  take: the cases the XDP fast path `XDP_PASS`es rather than dropping — a fragmented softwire IPv6 packet
  inbound (`STAT_DECAP_REASM_PASS`), an oversized outbound inner the fragmenter's guards rejected
  (`STAT_ENCAP_FRAG_SLOW`), and a decapped inner too big
  for a non-DF LAN egress (`STAT_DECAP_FRAG_SLOW`) — land on a `mm-dslite0` device (`local=B4`, `remote=AFTR`,
  mode ipip6, `encaplimit none`) and an IPv4 default route through it, so the kernel fragments the inner
  IPv4 to the tunnel MTU (WAN−40) and the ip6tnl encapsulates each piece, or reassembles the IPv6 fragments
  and the ip6tnl decapsulates. `tunnel.go` mirrors `internal/wanextend.HostRoutes`'s single-long-lived-socket,
  single-writer, log-on-teardown-failure shape: `New(wanMTU)` opens the socket and derives the tunnel MTU,
  `Ensure(b4, aftr)` replaces any stale device (a previous crashed run's) then creates+ups the device and
  adds the default route (fail-fast at startup — a home CPE has no other IPv4 path, and a missing
  `ip6_tunnel` module surfaces as an error rather than silent degradation), `SetEndpoints(b4, aftr)`
  repoints it in place (changelink, keeping the route) after an AFTR migration's cutover or a dynamic-B4
  hard switch (best-effort: a runtime failure only lags fragmentation, not the fast path),
  `SetSoftwireMTU(mtu)` re-derives the device MTU when the datapath learns a narrower softwire path MTU
  (same best-effort stance), and `Close()`
  deletes it best-effort on shutdown. `cmd/minuteman` creates it right after `SetB4Config` for every run
  (static or dynamic) and hands it to `startSoftwireControl` so the single endpoint owner can repoint it;
  its `defer Close()` runs after `bgWG.Wait()` (so the softwire control tree has stopped) but before
  `dp.Close()`.
- **`internal/fragpath`** — owns the companion veth pairs the in-XDP softwire fragmenter bounces its
  broadcast clones through (see the `bpf/datapath.bpf.c` fragmenter bullet for the two kernel constraints
  — devmap-enqueue MTU pre-check, per-device egress-program batching — that make one large-MTU pair *per
  fragment index* necessary): `mm-frag<i>` (the A end `frag_ports[i]` targets) / `mm-frag<i>p` (the B end
  `pkg/datapath` attaches `xdp_softwire_frag<i>` to), `NumPairs` = `datapath.MaxSoftwireFrags`, MTU 3456
  (as large as veth XDP attach allows on 4K pages — the attach ERANGEs beyond ~3.5KB), no IP (IPv6
  disabled via sysctl; stray kernel chatter is dropped by the trimming programs anyway). `MaxInnerLen`
  (`vethMTU − 48`) is the clone-admission ceiling handed to the datapath as `b4_config.frag_max_inner`.
  Endpoint-independent — the fragments carry whatever softwire addresses the encap wrote — so unlike
  `slowpath.Tunnel` it needs no repointing on an AFTR/B4 change. Same lifecycle shape as `slowpath`:
  long-lived netlink socket (via `pkg/netlink.AddVeth`), stale-device replacement, fail-fast `Ensure` at
  startup (`cmd/minuteman` wires it *before* `SetB4Config` sets `frag_unit`, so the datapath never
  engages the fragmenter without the plumbing behind it), best-effort `Close`.

When implementing new functionality, follow this split: per-packet fast-path logic goes in
`bpf/datapath.bpf.c`; anything that needs `cilium/ebpf` or knows about BPF map layouts goes in
`pkg/datapath`; generic protocol/wire-format code goes in its own `pkg/` package the way
`pkg/dhcpv6`/`pkg/aftrdiscovery`/`pkg/hb46pp`/`pkg/prefixdelegation`/`pkg/routeradvert`/`pkg/ndproxy`/
`pkg/netlink`/`pkg/dhcpv4`/`pkg/ethtool` do; CLI-specific glue and policy decisions belong in `internal/` or `cmd/` (e.g.
`internal/lanprefix`'s delegated-prefix-to-LAN-address and delegated-prefix-to-RA policy,
`internal/wanextend`'s WAN-prefix-discovery-to-RA and confirmed-target-to-host-route policy, or
`cmd/minuteman/ifstats.go` joining a netlink link dump, `pkg/datapath`'s program classification and
`pkg/ethtool`'s counters into one report), calling into
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
