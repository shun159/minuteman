# RFC compliance backlog

minuteman works as a DS-Lite B4 (verified end-to-end against the netns rig — see
`test/netns/README.md`), but measured strictly against the base RFC 7084 (IPv6 CE Router Requirements)
and RFC 6333, these gaps remain. Ordered by real-world impact, highest first. Last checked against the
codebase 2026-07-26. (RFC 7084's own updates — RFC 9096 renumbering reaction and RFC 9818 LAN-side
prefix delegation — are not targeted; see the RFC 9096 item in §3 and `docs/supported-rfcs.md`.)

Softwire fragmentation (RFC 6333 §5.3) is now addressed on both halves: reassembly by the
`internal/slowpath` companion `ip6tnl` (kernel reassembles before decapsulation), fragmentation by the
in-XDP outer-IPv6 fragmenter (`encap_fragment_outer` + the `internal/fragpath` companion veth pairs) —
see the resolved §1 below for the residual fallback cases that still take the old inner-IPv4 path.
Tunnel-originated ICMPv4 (decap-side Time Exceeded plus the RFC 6333 §5.7 well-known B4 address) is also
resolved and no longer tracked here, as is the DHCPv6-PD client-chosen-timer gap (a T1/T2 of 0 is now
resolved through `pkg/prefixdelegation`'s `effectiveTimers` per RFC 9915 §14.2, and an IA_PD with
T1 > T2 > 0 is discarded per §21.21 — exercised end-to-end by the rig's `MM_PD_ZERO_TIMERS=1` mode), and
so is the RA-worker restart that misapplied RFC 4861 §6.2.5: `pkg/routeradvert.Serve` now takes config
changes in place through a `routeradvert.Updater` (a size-1 latest-wins `Config` channel, applied
promptly but no sooner than §6.2.4's MIN_DELAY_BETWEEN_RAS after the previous RA), and both
`internal/lanprefix.RAManager.Sync` and `internal/wanextend`'s `raManager.sync` push updates instead of
cancel-and-restart — so a DHCPv6-PD Renew no longer emits the §6.2.5 RouterLifetime=0 (and RDNSS
Lifetime=0) shutdown RA that withdrew every LAN client's default route and DNS server once per T1
interval. Cancellation still emits it, for actual shutdowns. Verified in the rig's
`MM_PD_ZERO_TIMERS=1` mode by capturing the LAN's RAs (`tcpdump` in `mm-host`) across a real renewal:
the renewal drew one immediate RA carrying the refreshed prefix lifetimes with RouterLifetime still
1800s, and the only RouterLifetime=0 in the whole capture was the one minuteman sent on shutdown. What
this does *not* do is deprecate a superseded prefix when a renewal actually changes it (advertising the
old one with PreferredLifetime=0) — that's the RFC 9096 item in §3, and the restart it replaced didn't
do it either.

## 1. ~~Softwire fragmentation is inner-IPv4, not RFC-canonical outer-IPv6~~ — RESOLVED (in-XDP outer-IPv6 fragmentation); residual fallback cases remain

RFC 6333 §5.3 (with the original "The inner IPv4 packet MUST NOT be fragmented; fragmentation MUST happen
after encapsulation", and errata 5847 pointing at RFC 2473 §7.2(b), ignoring the DF bit) requires the B4 to
fragment the *outer IPv6* tunnel packet after encapsulation. The datapath now does exactly that, in XDP
(`encap_fragment_outer` + `emit_softwire_fragment` in `bpf/datapath.bpf.c`, plumbing in
`internal/fragpath`): an oversized inner IPv4 packet — **DF or not** — is encapsulated whole behind an
outer IPv6 header with a Fragment extension header, broadcast-cloned via a DEVMAP
(`bpf_redirect_map(BPF_F_BROADCAST)`, one clone per possible fragment), and each clone is trimmed to
fragment *i* and redirected out the WAN. The clones bounce through one large-MTU companion veth pair per
fragment index (`mm-frag<i>`/`mm-frag<i>p`) because of two kernel constraints: the devmap enqueue rejects a
frame larger than the target device's MTU *before* any egress program could trim it, and frames batched to
one target device all run the *first* enqueue's egress program, so per-fragment programs need per-fragment
devices. The encap-side ICMPv4 Fragmentation-Needed for oversized DF packets is gone with this — an
oversized DF packet is fragmented transparently, per the errata's DF-ignoring reading. Verified end-to-end
in the netns rig (`MM_SOFTWIRE_FRAG=1`): both DF and non-DF 1500-byte pings round-trip as two outer
fragments (`EncapFragXDP`/`EncapFragSeg` counters), and the reassembly half is unchanged
(`internal/slowpath`'s ip6tnl — kernel reassembles before decapsulation, §5.3-conformant since it landed).

**Residual (kernel ip6tnl fallback, counted as `EncapFragSlow`):** packets the XDP fragmenter can't take
still fall to the companion ip6tnl exactly as before — i.e. the kernel fragments the *inner* IPv4 (non-DF)
or PMTUD-signals (DF), which is a reachability fallback, not §5.3 conformance. That happens only when: the
inner packet needs more than `MAX_SOFTWIRE_FRAGS` (4) fragments or exceeds `fragpath.MaxInnerLen` (~3.4KB,
the veth single-buffer XDP ceiling) — only reachable with a jumbo-MTU LAN; the WAN device MTU shrank at
runtime below the startup-computed fragment size; or the fragmenter is unconfigured (degenerate WAN MTU).
On a standard WAN-1500 home deployment none of these occur. The netns rig covers the fallback directly
(`MM_SOFTWIRE_FRAG=1` temporarily shrinks the WAN MTU below the startup-computed fragment size, the one
trigger reachable from the LAN — the over-`MaxInnerLen` inner-size trigger is not, since the CPE's
XDP-attached LAN veth caps the pair's MTU so a client can't emit a >1500 inner packet): a DF oversized
packet then takes the ip6tnl fallback (`EncapFragSlow` advances, `EncapFragXDP` does not) and draws an
ICMPv4 Fragmentation-Needed (PMTUD) rather than blackholing.

## 2. Tunnel ICMPv6 relay — RFC 2473 §8

No reactive translation exists of an ICMPv6 error about the softwire packet itself (e.g. a Packet Too Big
or Time Exceeded from an intermediate IPv6 router on the B4↔AFTR path) into an ICMPv4 error toward the
original IPv4 sender. The encap path's own proactive `bpf_check_mtu`-based PtB only covers the
locally-known egress MTU, not a smaller MTU somewhere further along the IPv6 path.

## 3. Minor / acceptable for a home CPE

- During an AFTR graceful migration's drain window the softwire slow-path companion ip6tnl is repointed at
  the *new* AFTR at cutover. A *draining* flow's XDP-fragmented packets are unaffected (the in-XDP
  fragmenter reads the same per-packet next-hop slot as normal encap, so its fragments follow flow
  affinity), but the rare packet that falls to the ip6tnl *fallback* (see §1's residual) during a drain is
  encapsulated toward the new AFTR and dropped until the flow finishes — the fast path's dual-AFTR decap is
  unaffected.

- AFTR re-discovery flips the AFTR each refresh when the AFTR *name* has several AAAA records: the
  no-op check compares one resolved address (`aftrdiscovery` returns `addrs[0]`), not set membership.
  Benign at day-scale intervals — a graceful flow-affinity migration each time, not a hard break — but
  a proper fix exposes all resolved addresses and no-ops when the current AFTR is still among them.
- Dynamic-B4 change detection is polling (`cmd/minuteman`'s `watchB4`, ~30s), not event-driven. A netlink
  `RTNLGRP_IPV6_IFADDR` event subscription would react in sub-second but adds a new pkg/netlink surface
  plus debounce/DAD handling; home-CPE renumbering usually rides link events slower than a poll interval
  anyway, so this is a latency nicety, not a correctness gap.
- A WAN-address change hard-switches the softwire, breaking in-flight flows, because the AFTR's NAT
  state is keyed to the B4 address and dies with it. RFC 7785 §4 (Informational) recommends the AFTR
  migrate that state to the new B4 (Rec 3, using the last-seen B4 source address for return traffic) so a
  valid-but-deprecated old address could instead be drained — an operational SHOULD to hope for, not rely
  on. The per-slot `b4_addr` already supports a future drain. (This is not a DHCPv6 / RFC 9915 behaviour:
  RFC 9915 defines only periodic Information-Refresh-Time refresh (§21.23 / §18.2.12), not a
  link/address-change re-discovery trigger — the B4-address-change trigger is the RFC 7785 concern above.)
- RDNSS is only advertised while `-dns-proxy` is on; with it off (the default), an IPv6-only SLAAC LAN
  client is DNS-less again (RFC 7084 §L-11). The proxy-less alternative — advertising the WAN-learned
  upstream resolvers directly in RDNSS — would cover the default configuration too. Also, §L-11 asks for
  both RDNSS *and* the DNS Search List (DNSSL) option; minuteman sends only RDNSS.
- RFC 7084's renumbering update (RFC 9096) isn't implemented, and it is now the most relevant gap given
  dynamic B4 handles WAN renumbering. Most actionable: L-15/L-16 (LAN SLAAC/DHCPv6-PD lifetimes MUST/SHOULD
  be capped to the WAN prefix's *remaining* lifetime) — `internal/lanprefix` currently advertises the
  delegated prefix's own lifetimes without capping to what the WAN prefix has left. Also L-13 (signal
  stale config) and WPD-9/WPD-10 (don't auto-RELEASE on restart; stable WAN IAID — `pkg/prefixdelegation`
  already uses a fixed client IAID, so WPD-10 is likely met, but it does send a shutdown Release). RFC 7084's
  other update, RFC 9818 (LAN-side prefix delegation, LPD-1..LPD-10), is out of scope for a single-tier CPE.
- RA MTU option (RFC 4861 §4.6.4) isn't advertised.
- MLD (RFC 3810) is left entirely to the kernel — minuteman forwards no IPv6 multicast of its own. Fine
  for a home gateway; would need revisiting for a router expected to do multicast routing.
- RFC 4389 proxy-loop detection is a documented non-goal of `pkg/ndproxy`; fine while WAN and LAN
  can't be accidentally bridged, worth revisiting otherwise.
- ICMP error quotes are fixed-size: the ICMPv6 Packet Too Big quotes only the invoking IPv6 header +
  8 bytes, where RFC 4443 asks for as much as fits in the minimum MTU. Enough for every real PMTUD
  consumer (ports/flow are within the 8 bytes); a full quote would need variable-length reply
  construction in XDP.
