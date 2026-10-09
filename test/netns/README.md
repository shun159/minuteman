# netns DS-Lite rig

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
packets cross the softwire during a DNS-proxied query (see `pkg/dnsproxy`'s own entry in CLAUDE.md's
Architecture for why that's structurally guaranteed, not just empirically true this once).

A fourth, independent toggle, `MM_DHCPV4` (`0` default or `1`), adds `-dhcpv4` and exercises the DHCPv4
server. Because a LAN client can no longer be given a static IPv4 (it must obtain one from the server),
`setup.sh` in this mode leaves `mm-host` without a static address or default route, and `smoketest.sh` — as
its very first check, before anything else assumes the host has IPv4 — runs a real `dhclient` in `mm-host`
to acquire them, then asserts the pool's first address (`.2`), the gateway default route, and the
DS-Lite-adjusted interface MTU (`1460`, from option 26) all landed; every later check (DNS proxy, the
DS-Lite data path) then runs over that DHCP-assigned config, so the whole rig doubles as an end-to-end
DHCPv4 test. `dhclient` is given a small conf requesting `interface-mtu` so it applies option 26, and a
`dhclient-script` of its own (`-sf`) that applies the address, default route and MTU and nothing else: the
system script would write the DNS server minuteman hands out to `/etc/resolv.conf`, and `ip netns exec`
separates a namespace's network, not its `/etc` -- that would be the host's resolv.conf.
`teardown.sh` also stops any `dhclient` left running in `mm-host`.

A fifth, independent toggle, `MM_DUALSTACK` (`0` default or `1`), exercises RFC 6333's core dual-stack
premise — a DS-Lite B4 tunnels *only* IPv4; native IPv6 is forwarded directly, never through the softwire.
It changes no minuteman flag (that behavior is inherent to `xdp_dslite_encap`, which only ever matches
`ETH_P_IP` and `XDP_PASS`es everything else — see CLAUDE.md's datapath entry): `setup.sh` instead
gives `mm-inet` a *native* IPv6 address (`2001:db8:beef::/64`, a second subnet on the aftr↔inet link)
alongside its IPv4, wires the native-IPv6 forwarding path (`mm-aftr` becomes a plain IPv6 router for that
subnet in addition to its DS-Lite decap role — `net.ipv6.conf.all.forwarding=1`; `mm-isp` learns a route to
it, plus — in `dhcpv6-pd` mode only — a return route to the delegated `/56` via `mm-cpe`'s pinned WAN
address, since Kea delegates but installs no kernel route; in `ndproxy` mode the return path is already
on-link via minuteman's RFC 4389 proxying), and has dnsmasq serve one FQDN (`dualstack.example.com`) with
both an `A` and an `AAAA` record. `smoketest.sh` then asserts `mm-host` holds both an IPv4 (static or
DHCPv4) and a global SLAAC IPv6 address, resolves the FQDN once per family, and — capturing on the AFTR's
`dslite0` throughout — confirms the `A`/IPv4 ping reaches `mm-inet` *and crosses* the tunnel (a non-zero
packet count, the positive control) while the `AAAA`/IPv6 ping reaches `mm-inet` natively with *zero*
packets on `dslite0`. In this mode `smoketest.sh` also proves the native-IPv6 path was carried by
minuteman's *XDP forwarding fastpath* rather than the kernel slow path (which the dslite0/reachability
checks alone can't distinguish): it asserts the datapath `IPv6Fwd` counter advanced across the section,
read out-of-band from the bpffs-pinned stats map via the `minuteman stats` subcommand (see "Reading
datapath stats" below). A further independent toggle, `MM_IPV6_SW_RSS` (`0` default or `1`),
adds `-ipv6-sw-rss` to that invocation and additionally asserts the `IPv6RSSRedirect` counter advanced
(the cpumap fanout engaged). Composes with all four toggles above; pairs naturally with `MM_DHCPV4=1` for
the "host has both a DHCPv4 and an IPv6 address" case.

A seventh independent toggle, `MM_DYNAMIC_B4` (`0` default or `1`), starts minuteman *without* `-b4` so it
selects the softwire source dynamically from the WAN's kernel-chosen source toward the AFTR (RFC 6724) and
re-selects it when the WAN address changes (the DS-Lite B4-address change of RFC 7785). `smoketest.sh` first asserts minuteman logged the
startup selection (`WAN_CPE_ADDR`), then drives a renumbering scenario: it adds a second WAN global and
deprecates the first (`preferred_lft 0`), waits out minuteman's 30s B4 poll for the hard-switch
(parsing the re-selected address from the log rather than assuming it is `WAN_CPE_ADDR2`), points the AFTR's `ip6tnl` `remote` at it (the
NAT-state-follows-the-address step a real AFTR does via its own B4 re-learning), and re-runs the DS-Lite
data-path check — which only passes if the switch actually took. In this mode `setup.sh` turns SLAAC off on
`mm-cpe`'s WAN (`autoconf=0`, RAs still accepted for the default route), so `WAN_CPE_ADDR` is its only global
at startup: with a SLAAC address beside it, which of the two the kernel prefers would depend on which finishes
DAD first after `AttachWAN` bounces the link, while the AFTR's tunnel is pinned to `WAN_CPE_ADDR`. Composes
with the other toggles.

An eighth independent toggle, `MM_SOFTWIRE_FRAG` (`0` default or `1`), exercises softwire fragmentation
(RFC 6333 §5.3) in both directions. It changes no minuteman flag and adds no topology — every link is
already 1500; outbound the in-XDP outer-IPv6 fragmenter (and its `mm-frag*` companion veth pairs) does the
work, inbound the companion `ip6tnl` minuteman creates in `mm-cpe` — the counters are read out-of-band via
`minuteman stats`. `smoketest.sh` then (a) checks the companion ip6tnl and its IPv4 default route exist,
(b) sends an oversized *non-DF* ping **and** an oversized *DF* one — both must round-trip, since the B4
encapsulates the packet whole and fragments the *outer IPv6* in XDP, ignoring DF per errata 5847
(asserting `EncapFragXDP` advances, `EncapFragSeg` is exactly 2× it, and the `EncapFragSlow` ip6tnl
fallback stays untouched), and (c) hand-crafts a fragmented softwire packet toward the
B4 with `send-softwire-fragments.py` (a real Linux AFTR never emits outer-IPv6 fragments, so it can't be
driven from the rig's own traffic) so the decap must `XDP_PASS` it for kernel reassembly — asserting the
inner echo reaches the LAN client and reappears in `DecapReasmPass`. It then also (d) exercises the encap
*fallback* the fast path can't take (backlog §1's residual note): it temporarily shrinks the WAN link's MTU
below the fragment size `frag_unit` was computed from at startup, so an oversized *DF* ping falls to the
kernel `ip6tnl` instead of the in-XDP fragmenter, and asserts `EncapFragSlow` advances, `EncapFragXDP` does
*not*, and — the specific regression risk from this PR routing DF packets to the fallback — the client
receives an ICMPv4 Fragmentation-Needed (PMTUD, captured on the LAN) rather than a silent blackhole, then
restores the MTU. (The over-`MaxInnerLen` inner-size trigger isn't reachable from the LAN here: the CPE's
XDP-attached LAN veth caps the pair's MTU, so a client can't emit a >1500 inner packet in the first place —
which is also why that residual is genuinely unreachable on a standard 1500 deployment.) Composes with the
other toggles.

A ninth independent toggle, `MM_PD_ZERO_TIMERS` (`0` default or `1`, `dhcpv6-pd` mode only — `setup.sh`
rejects the `ndproxy` combination, which has no delegation to time), makes Kea delegate with `T1 = T2 = 0`:
the RFC 9915 §21.21 way for a delegating router to leave the renewal timing to the requesting router, which
§14.2 then requires to choose its own times without transmitting immediately. Kea is asked for it by
disabling `calculate-tee-times` and omitting `renew-timer`/`rebind-timer`, and the prefix's lifetimes drop
to 130s/260s (from 3600/7200) so the T1 minuteman derives — 0.5 × the shortest preferred lifetime, §21.21's
own recommended ratio — is 65s and a real renewal lands inside one smoketest run. It changes no minuteman
flag. `smoketest.sh` asserts the derived timers in the lease log line (`renew in 1m5s, rebind in 1m44s`),
then, as its very last check so everything else overlaps the wait, waits the T1 out and asserts minuteman
renewed on it: at least one renewal happened, Kea's own log recorded receiving the Renew, the delegated
prefix and its carved LAN address are unchanged across it, and — the actual regression this guards — the
number of lease applications stays within what the client's own timers permit (taking `T1 = 0` literally
renewed on every exchange RTT, hundreds of times over the same window). Adds ~90s to the run, in this mode
only.

A tenth independent toggle, `MM_TUNNEL_ICMP` (`0` default or `1`), exercises the tunnel ICMPv6 relay
(RFC 2473 §8) — an ICMPv6 error an intermediate IPv6 router on the B4↔AFTR path sends *about a softwire
packet*, which the B4 has to turn into an ICMPv4 error toward the LAN client whose packet it quoted.
It changes no minuteman flag (the relay, like DS-Lite's own forwarding, is always on) and runs in two
halves. First, deterministically: `send-softwire-fragments.py`'s `icmp6ptb`/`icmp6texc`/`icmp6unreach`
modes inject each error type from `mm-isp`, and `smoketest.sh` asserts the ICMPv4 that appears on the LAN
is the right type (RFC 7915 §5.3's mapping: Packet Too Big → Fragmentation Needed with the 40-byte tunnel
overhead deducted, Time Exceeded → Time Exceeded — explicitly *not* Host Unreachable, which is what the
kernel `ip6tnl` produced for this before — Destination Unreachable → its ICMPv4 counterpart) and is
sourced from the well-known B4 address `192.0.0.2` (RFC 6333 §5.7), with `TunnelICMPRelay` advancing; an
`icmp6bogus` error quoting a softwire between two addresses that are *not* this B4's must be ignored
outright, since believing one would let anyone on the IPv6 internet inject ICMPv4 errors into the LAN or
talk the B4 into a smaller path MTU. Second, for real: it narrows the ISP↔AFTR core link to 1400 while
leaving the CPE's own WAN at 1500 — so nothing local can see the narrowing and learning it from the
resulting Packet Too Big is the only way the fragmenter stops emitting fragments the path can only drop —
and asserts minuteman learns that path MTU (`TunnelPMTU`, and the log line `softwire path MTU: 1400`),
re-sizes the companion `ip6tnl` to match (1360), re-derives the automatic TCP MSS clamp from it (a
connection opened after the narrowing offers `mss 1320`, the third consumer of a learned reading), and then
carries oversized non-DF **and** DF traffic
across the narrowed path with no loss and no PMTUD signal at all, still via the in-XDP fragmenter
(`EncapFragXDP`), before restoring the link. It runs as the last datapath section on purpose: a learned
path MTU stays in force for ten minutes (`datapath.TunnelPMTUExpiry`), which would re-size the fragments
the `MM_SOFTWIRE_FRAG` checks assert on. Composes with the other toggles.

Independently of `MM_SOFTWIRE_FRAG`, `smoketest.sh` also hand-crafts a whole softwire packet whose inner
IPv4 TTL is 1, and asserts that the B4 returns a softwire-encapsulated ICMPv4 Time Exceeded toward the
AFTR, sourced from the DS-Lite well-known B4 address `192.0.0.2`, with the `ICMPTimeExceeded` counter
advancing.

`run-cpe.sh` and `smoketest.sh` deliberately omit `-aftr` so minuteman discovers it live against the rig —
pass `-aftr <addr>` as an extra argument to either script to override with a static address instead.

## Reading datapath stats

While minuteman runs, the datapath's per-path counters are readable out-of-band from the stats map it
pins to bpffs — no `-stats-interval` logging or ownership of its stdout needed:

```sh
sudo bin/minuteman stats            # one `Name: value` line per counter
sudo bin/minuteman stats --json     # e.g. ... | jq .DecapMartian
sudo bpftool map dump pinned /sys/fs/bpf/minuteman/stats
```

This is why both scripts start minuteman via `nsenter --net=/var/run/netns/mm-cpe` rather than
`ip netns exec mm-cpe`: the latter also creates a new mount namespace and remounts `/sys`, so the pin
would land on a private bpffs no later process can see. `nsenter --net` switches only the network
namespace, keeping the host's `/sys/fs/bpf`, so the commands above work from the host while the rig runs
(pins are mount-namespace state, not netns state). `smoketest.sh`'s counter assertions (`read_stat`) are
before/after deltas over this same subcommand.

`stats interfaces` reports each XDP-bound interface's driver counters (the `ethtool -S` set) instead.
Those interfaces live in `mm-cpe`, so unlike the commands above it has to be run *inside* the namespace
— which still works because `nsenter --net` leaves the host's `/sys/fs/bpf` in place:

```sh
sudo nsenter --net=/var/run/netns/mm-cpe bin/minuteman stats interfaces
```

It's the quickest way to see the softwire fragmenter working under `MM_SOFTWIRE_FRAG=1`: each
`mm-frag<i>p` companion veth shows `rx_queue_0_xdp_redirect` for the clones it turned into a real
fragment and `rx_queue_0_xdp_drops` for the ones the packet didn't need, which should add up to the
`EncapFragSeg`/`EncapFragXDP` counters above.

`smoketest.sh` asserts both subcommands on every run (its `iface_stats` helper): that the interface
list the kernel-derived role classification produces really is the WAN, the LAN and all four
fragmenter companion veths, and that `stats --json` / `stats interfaces --json` decode as the object
and the array their consumers walk. With `MM_SOFTWIRE_FRAG=1` it also checks the frag-role interfaces
report a non-zero `xdp_redirect`, tying the datapath's own `EncapFragSeg` to the clones the companion
veths actually forwarded.

Two things worth knowing if you touch these scripts:
- `mm-cpe` needs both `net.ipv4.ip_forward=1` and `net.ipv6.conf.all.forwarding=1`, or `bpf_fib_lookup()` in
  the datapath returns `BPF_FIB_LKUP_RET_FWD_DISABLED` for every packet and nothing gets encapsulated;
  `net.ipv6.conf.<if>.accept_ra=2` is then needed on top so RA/SLAAC still works with forwarding on.
  `setup.sh` no longer sets these itself — `pkg/datapath.Loader.AttachWAN` does (see CLAUDE.md's
  Architecture), so they're applied whenever minuteman runs, not just inside this test rig.
- mm-isp's dnsmasq must be started, and mm-cpe's WAN link brought up, in that order — Linux only retries
  Router Solicitation a few times right after an interface comes up, so if the RA server isn't listening yet
  the CPE gives up and never gets a default route; `setup.sh` sequences this deliberately, don't reorder it.
  Likewise the `dhcp-range=::,constructor:<iface>,ra-only` form is required (not bare `::`) or dnsmasq
  never actually replies to Router Solicitations despite logging that RA is enabled.

The AFTR's decap step — and, since the softwire fragmentation slow path, minuteman's own companion device
in `mm-cpe` — uses a kernel `ip6tnl` (mode `ipip6`) device, which needs the `ip6_tunnel` module.
`setup.sh` checks for it up front with a specific diagnostic for the common Arch situation where a kernel
package upgrade has replaced `/lib/modules/<old-version>/` before a reboot, leaving the currently *running*
kernel without a matching module directory (`uname -r` disagrees with what's on disk) — reboot to fix that.

## Verified-passing combinations

The full smoketest (AFTR discovery, LAN IPv6 reachability, LAN IPv4 provisioning, TCP MSS clamping, and the
DS-Lite data path
end-to-end through the AFTR's decap+NAPT44 to the simulated internet and back, ICMP and TCP) has been
verified passing from a fresh setup for:
- the default combination (`dhcpv6` AFTR discovery + `dhcpv6-pd`, no toggles), which is also where TCP MSS
  clamping is asserted unconditionally: the LAN client's SYN reaching the AFTR and the remote's SYN-ACK
  reaching the LAN client both advertising `mss 1420` (the rig's 1500 WAN MTU less 40 + 40), the connection
  completing (so the hand-rolled TCP checksum fixup is right), and `MSSClamped` advancing once per direction
- `MM_AFTR_DISCOVERY=dhcpv6`/`hb46pp` (both against the `dhcpv6-pd` WAN model)
- `MM_WAN_MODEL=dhcpv6-pd`/`ndproxy` (both against `dhcpv6` AFTR discovery)
- `MM_DNS_PROXY=1`
- `MM_DHCPV4=1` (against both `dhcpv6`/`dhcpv6-pd`)
- `MM_DUALSTACK=1` (against both WAN models, one with `MM_DHCPV4=1`) plus `MM_IPV6_SW_RSS=1`; the
  datapath's ICMPv6-Packet-Too-Big origination was verified separately by forcing a small WAN egress MTU
  and confirming a LAN client caches the advertised path MTU
- `MM_DYNAMIC_B4=1` (against `dhcpv6` AFTR discovery + `dhcpv6-pd`): startup dynamic B4 selection plus the
  WAN-renumbering hard-switch and softwire recovery, all end-to-end
- `MM_SOFTWIRE_FRAG=1` (against `dhcpv6` AFTR discovery + `dhcpv6-pd`): both fragmentation directions
  end-to-end — oversized non-DF *and* DF pings both round-tripping as two outer-IPv6 fragments via the
  in-XDP fragmenter (with `EncapFragXDP`/`EncapFragSeg` advancing and the `EncapFragSlow` ip6tnl fallback
  untouched; the on-wire fragments were also confirmed by tcpdump on the ISP link — correct offsets,
  M flags, and a shared ID per packet), a hand-crafted fragmented
  softwire packet reassembled and delivered to the LAN client (with `DecapReasmPass` advancing), and the
  encap ip6tnl *fallback* forced by a runtime WAN-MTU shrink: a DF oversized packet takes the fallback
  (`EncapFragSlow` advancing, `EncapFragXDP` untouched) and draws an ICMPv4 Fragmentation-Needed on the LAN.
  Re-run 2026-08-09 after the `stats` / `stats interfaces` subcommand split (33/33 checks), which is also
  where the new unconditional stats assertions were verified — both JSON shapes decoding, the roles
  reported for the WAN veth, the LAN veth and all four companion veths — along with `xdp_redirect` summing
  to 8 across the frag-role interfaces, i.e. the two fragments each of the four oversized pings needed
- `MM_TUNNEL_ICMP=1` (against `dhcpv6` AFTR discovery + `dhcpv6-pd`, alongside `MM_SOFTWIRE_FRAG=1`): all
  three injected error types relayed with the right ICMPv4 type and the `192.0.0.2` source, a bogus quote
  ignored, and the narrowed-core-link half end-to-end — the learned path MTU applied to both the
  fragmenter (fragments confirmed on the ISP link as `frag (0|1352)` + `frag (1352|148)`, i.e. outer
  packets of 1400 and 196), the companion `ip6tnl`, and the automatic TCP MSS clamp (a connection opened
  after the narrowing offering `mss 1320`), with oversized DF and non-DF pings then at 0% loss
- `MM_PD_ZERO_TIMERS=1` (against `dhcpv6` AFTR discovery + `dhcpv6-pd`): Kea delegating with `T1 = T2 = 0`,
  minuteman deriving 65s/104s from the 130s preferred lifetime and renewing exactly once on that timer
  within an 85s window (Kea logging the single `RENEW`, the prefix unchanged across it). Re-run after the
  RA in-place-update change (`routeradvert.Updater`) with a `tcpdump` on `mm-host`'s LAN link alongside
  it, since this is the mode where a renewal actually lands inside one run: the renewal drew a single
  immediate RA carrying the refreshed prefix lifetimes at `router lifetime 1800s`, and the only
  `router lifetime 0s` RA in the capture was minuteman's own shutdown one. The smoketest itself doesn't
  assert this (it never inspects RAs beyond the client's SLAAC result), so verifying it again means
  capturing again:
  `sudo ip netns exec mm-host tcpdump -i v-host-cpe -v "icmp6 and ip6[40] == 134"`
- the default (all toggles off), re-run after the `xdp_dslite_encap` non-unicast-bypass change to confirm
  no regression, and again after the DHCPv6-PD client-chosen-timer change (server-set `T1`/`T2` still used
  verbatim: `renew in 30m0s, rebind in 48m0s` from Kea's 1800/2880)

The uncrossed corners of these independent axes haven't each been re-run, but they are independent code
paths (AFTR discovery, LAN IPv6 provisioning, DNS forwarding, LAN IPv4 provisioning, native-IPv6
dual-stack, IPv6 software RSS) with no shared state.

Datapath review regressions are included in the existing modes:
`MM_SOFTWIRE_FRAG=1` lowers the LAN MTU to exercise decap FIB `FRAG_NEEDED`
and checks an oversized off-LAN packet is still classified as martian.
`MM_DUALSTACK=1` lowers WAN MTU and captures the native IPv6 Packet Too Big;
combine it with `MM_IPV6_SW_RSS=1` to cover the CPUMAP reply path.
`MM_TUNNEL_ICMP=1` injects correct softwire endpoints with a non-LAN quoted
source, both DF and non-DF, and checks neither updates the PMTU map.
The deterministic per-clone PMTU-update test is separate:
`sudo env MM_BPF_TEST=1 go test ./pkg/datapath -run TestFragmentUnitSnapshot -v`.
