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
DHCPv4 test. `dhclient` is given a small conf requesting `interface-mtu` so it applies option 26.
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
checks alone can't distinguish): it starts minuteman with `-stats-interval 2s` and asserts the logged
datapath `IPv6Fwd` counter advanced. A further independent toggle, `MM_IPV6_SW_RSS` (`0` default or `1`),
adds `-ipv6-sw-rss` to that invocation and additionally asserts the `IPv6RSSRedirect` counter advanced
(the cpumap fanout engaged). Composes with all four toggles above; pairs naturally with `MM_DHCPV4=1` for
the "host has both a DHCPv4 and an IPv6 address" case.

`run-cpe.sh` and `smoketest.sh` deliberately omit `-aftr` so minuteman discovers it live against the rig —
pass `-aftr <addr>` as an extra argument to either script to override with a static address instead.

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

The AFTR's decap step uses a kernel `ip6tnl` (mode `ipip6`) device, which needs the `ip6_tunnel` module.
`setup.sh` checks for it up front with a specific diagnostic for the common Arch situation where a kernel
package upgrade has replaced `/lib/modules/<old-version>/` before a reboot, leaving the currently *running*
kernel without a matching module directory (`uname -r` disagrees with what's on disk) — reboot to fix that.

## Verified-passing combinations

The full smoketest (AFTR discovery, LAN IPv6 reachability, LAN IPv4 provisioning, and the DS-Lite data path
end-to-end through the AFTR's decap+NAPT44 to the simulated internet and back, ICMP and TCP) has been
verified passing from a fresh setup for:
- `MM_AFTR_DISCOVERY=dhcpv6`/`hb46pp` (both against the `dhcpv6-pd` WAN model)
- `MM_WAN_MODEL=dhcpv6-pd`/`ndproxy` (both against `dhcpv6` AFTR discovery)
- `MM_DNS_PROXY=1`
- `MM_DHCPV4=1` (against both `dhcpv6`/`dhcpv6-pd`)
- `MM_DUALSTACK=1` (against both WAN models, one with `MM_DHCPV4=1`) plus `MM_IPV6_SW_RSS=1`; the
  datapath's ICMPv6-Packet-Too-Big origination was verified separately by forcing a small WAN egress MTU
  and confirming a LAN client caches the advertised path MTU
- the default (all toggles off), re-run after the `xdp_dslite_encap` non-unicast-bypass change to confirm
  no regression

The uncrossed corners of these independent axes haven't each been re-run, but they are independent code
paths (AFTR discovery, LAN IPv6 provisioning, DNS forwarding, LAN IPv4 provisioning, native-IPv6
dual-stack, IPv6 software RSS) with no shared state.
