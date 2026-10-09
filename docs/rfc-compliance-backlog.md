# RFC compliance backlog

minuteman works as a DS-Lite B4 (verified end-to-end against the netns rig — see
`test/netns/README.md`), but measured strictly against the base RFC 7084 (IPv6 CE Router Requirements)
and RFC 6333, these gaps remain. Ordered by real-world impact, highest first. Last checked against the
codebase 2026-08-07. (RFC 7084's own updates — RFC 9096 renumbering reaction and RFC 9818 LAN-side
prefix delegation — are not targeted; see the RFC 9096 item in §4 and `docs/supported-rfcs.md`.)

§3 and two §4 items come from a carrier spec rather than an RFC: NTT East's *IP通信網サービスの
インタフェース－フレッツシリーズ－* 第三分冊, 第46版 (dated 2026-04-30,
<https://flets.com/pdf/ip-int-3.pdf>) — the IPoE access spec minuteman's own target deployment runs on.
That edition covers three access tiers in separate 編 (volumes) whose IPv6 provisioning rules differ, and
those differences are what make the gaps concrete rather than hypothetical:

| 編 | section | LAN prefix source | RA M/O flags | Information-Request |
|---|---|---|---|---|
| フレッツ 光ネクスト | §2.4.2.1.2 (printed p. 62, PDF p. 76) | the RA's 64-bit prefix **or** DHCPv6-PD's 48/56-bit one — the spec lists both as the only usable sources | 「1が設定される場合があります」; on M=1, DHCPv6-PD is 推奨 (recommended); Preferred Lifetime may be 0 | 推奨 on O=1, so the network answers it |
| フレッツ 光クロス | §4.4.2.1.2 (printed p. 23, PDF p. 37) | DHCPv6-PD /56 only (推奨) | 「1を設定される場合があります」, with no stated meaning | 「IP通信網はInformation-Requestには対応しておりません」 |
| フレッツ 光25G | §2.4.1.1.2 (printed p. 6, PDF p. 20) | DHCPv6-PD /56 only (「委譲を受けるものとします」) | not mentioned; the RA is stated to be for routing/control information, 「IPv6アドレスの自動設定を目的とするものではありません」 | 「IP通信網はInformation-Requestには対応しておりません」 |

So the RA's M flag discriminates minuteman's two LAN provisioning models (`-dhcpv6-pd` vs `-ndproxy`)
only on 光ネクスト; the other two tiers are PD-only, and on them the DHCPv6 exchange minuteman opens with
is one the network states it does not answer (§3). Requirements of those sections that minuteman already
meets: DHCPv6 yields no 128-bit address (minuteman requests IA_PD only), the client DUID must be DUID-LL
from a MAC and as stable as possible (`pkg/dhcpv6/duid.go`, a pure function of the WAN MAC), and a
delegation is a /48 or /56 (`lanprefix.SubnetFor` carves a /64 out of any delegation up to /64).

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
old one with PreferredLifetime=0) — that's the RFC 9096 item in §4, and the restart it replaced didn't
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

## 2. ~~Tunnel ICMPv6 relay~~ — RESOLVED (in-XDP relay + learned softwire path MTU), RFC 2473 §8

An ICMPv6 error about the softwire packet itself — a Packet Too Big or Time Exceeded from an intermediate
IPv6 router on the B4↔AFTR path — is now translated in the datapath into an ICMPv4 error toward the
original IPv4 sender (`handle_tunnel_icmpv6` in `bpf/datapath.bpf.c`), and a Packet Too Big additionally
teaches the encap side a path MTU its own `bpf_check_mtu` can never see (that only covers the local WAN
device). Type mapping follows RFC 7915 §5.3; the reply is sourced from the well-known B4 address
`192.0.0.2` (RFC 6333 §5.7) like every other ICMPv4 error this datapath originates, and goes through the
same RFC 1812 §4.3.2.7 eligibility gate and per-CPU rate limiter.

Two details worth keeping in mind:

- **Packet Too Big is relayed only for a DF quote.** Without DF the sender can't act on a next-hop MTU,
  and this B4's answer is instead to fragment the outer IPv6 at the learned MTU (RFC 6333 §5.3 /
  errata 5847 → RFC 2473 §7.2(b), the same DF-ignoring stance §1 above settled on). That error is
  *consumed* rather than passed up, since the kernel would otherwise relay the very signal minuteman
  deliberately isn't sending.
- **The learned MTU is acted on in two places with two different owners.** Encap clamps its effective MTU
  against it per packet (`tunnel_pmtu_for`), immediately. The fragment size (`b4_config.frag_unit`) and
  the companion ip6tnl's device MTU are recomputed by userspace instead (`cmd/minuteman`'s
  `watchTunnelPMTU`, a 2s tick), because `encap_fragment_outer` and the `xdp_softwire_frag<i>` programs
  read `frag_unit` at different moments for the same packet — a value that changed in between would
  produce a fragment set that can never reassemble. In the seconds between the two, an oversized packet
  takes the ip6tnl fallback (`EncapFragSlow`) rather than being fragmented too big. Readings age out after
  10 minutes on both sides, so a path that widens again needs no announcement.

**What this replaced.** Measured against the netns rig on kernel 7.0.11 before the change: an ICMPv6
Packet Too Big about a softwire packet *was* already reaching the LAN client as an ICMPv4 Fragmentation
Needed — not from the datapath, but from the kernel, via the `internal/slowpath` companion ip6tnl's own
error handling. So the softwire was not opaque to PMTUD in practice. What the kernel path did *not* do,
and this does: it sourced the error from a LAN gateway address rather than `192.0.0.2`; it translated
ICMPv6 Time Exceeded into ICMPv4 **Host Unreachable** rather than Time Exceeded; it relayed nothing at all
when the quote was small (a synthetic 60-byte quote drew no relay, a real router's ~1232-byte one did);
and, most consequentially, none of it reached the XDP fragmenter, which kept slicing to the WAN device's
MTU and so kept handing the narrow path fragments it could only drop — every oversized packet costing a
round of Packet Too Big plus client-side re-fragmentation, and non-DF traffic depending entirely on the
client honouring a relayed ICMPv4 error to get through at all.

Verified end-to-end in the netns rig (`MM_TUNNEL_ICMP=1`): each error type injected and relayed with the
right ICMPv4 type and source, an error quoting someone else's softwire ignored, and — with the ISP↔AFTR
core link narrowed to 1400 while the CPE's WAN stays at 1500 — the learned MTU applied to both the
fragmenter and the companion ip6tnl, after which oversized DF *and* non-DF traffic crosses at 0% loss.

## 3. ~~AFTR discovery blocks forever on a network that doesn't answer Information-Request~~ — RESOLVED (bounded Information-Request + PD-sourced resolvers for the HB46PP fallback)

Both the 光クロス and 光25G 編 of the carrier spec above state
「IP通信網はInformation-Requestには対応しておりません」(§4.4.2.1.2 / §2.4.1.1.2), and transix has offered
DS-Lite over 光クロス since 2020-04-01 (<https://www.mfeed.ad.jp/ja/2020/2020-03-26/>) — so a network that
never answers minuteman's opening DHCPv6 message is a real target deployment, not a hypothetical. It used
to hang startup outright: `dhcpv6.InformationRequest` follows RFC 3315 §18.1.5, which sets no maximum
retransmission count and no maximum duration, so it retried forever (backoff merely capped at `InfMaxRT`,
3600s) and `aftrdiscovery.Discover` never returned. `resolveAFTR`'s retry loop only turns when
`discoverAFTROnce` *returns*, so it never turned, and the HB46PP fallback — which exists for exactly these
deployments — was never reached, since `discoverAFTROnce` entered it only on
`aftrdiscovery.ErrNoAFTRName`, which by construction requires a Reply.

Three changes, because bounding the wait alone would only have converted the hang into a fallback with no
resolvers to work with:

- **`aftrdiscovery.Discover` takes a `replyTimeout`** bounding the Information-Request phase only (not the
  AFTR-name DNS resolution that follows, so a timeout unambiguously means "nothing answered") and reports
  the new `ErrNoReply` sentinel when it expires. Zero or negative keeps the RFC-correct unbounded
  behavior; `cmd/minuteman` passes `informationRequestTimeout`, 30s, about five retransmissions at
  §18.1.5's 1s-and-doubling schedule. `discoverAFTROnce` now has two routes into HB46PP —
  `ErrNoAFTRName` (resolvers from the partial Reply) and `ErrNoReply` (resolvers from the PD lease).
- **The PD exchange asks for DNS servers.** `pkg/prefixdelegation`'s Solicit/Request/Renew/Rebind carry an
  `OPTION_ORO` for `OPTION_DNS_SERVERS` (`requestedOptions` in `acquire.go`) and the granting Reply's
  servers land on `Lease.DNSServers`. The spec says DNS servers are obtainable over DHCPv6 on those tiers
  (§4.4.2.1.3 / §2.4.1.1.3) — just not via Information-Request, so the stateful exchange is the only
  source. The RFC 3646 decoding moved to `dhcpv6.Options.DNSServers()` rather than being duplicated, since
  `pkg/aftrdiscovery` reads the same option.
- **`run()` acquires the PD lease before AFTR discovery**, and hands its servers to `resolveAFTR`,
  the re-discovery of `internal/softwirectl`, and (behind `-dns-server` and the discovery-learned set) `-dns-proxy`'s upstreams.
  Only the `Acquire` call moved; `runPrefixDelegation` now takes the already-acquired lease and does the
  LAN assignment, RA workers and `Maintain` in its old position. Both exchanges go through the WAN's one
  DHCPv6 client (`internal/dhcpv6client`), which runs them one at a time, so their concurrency is unchanged.

One judgement call worth recording: a failure reached *through* `ErrNoReply` has its retry delay capped at
`noReplyRetryCap` (5 min) by `retryDelayFor`, rather than taking `hb46pp.RetryDelay`'s verdict as-is. That
verdict can be 1–3 hours for `ErrNotProvisioned`, and having heard nothing at all from DHCPv6 there is no
evidence the network is HB46PP-unprovisioned rather than merely slow to come up — hours of no IPv4 is a
steep price for a guess made on no data. Attempts that did draw a Reply keep the spec's full backoff.

Verified end-to-end in the netns rig by reproducing the carrier-spec shape directly: with the rig in
`MM_AFTR_DISCOVERY=hb46pp` mode and an nftables rule in mm-isp dropping *only* DHCPv6 message type 11
(`udp dport 547 @th,64,8 11 drop`, so the PD exchange still completes), minuteman acquired the delegation
first (DNS servers `fd00:1::1`, carried by the new ORO), retransmitted the Information-Request five times
into the blackhole, gave up at exactly 30s, fell forward to HB46PP with the lease's servers, and brought
the whole datapath up 1s later. The unmodified rig (`MM_AFTR_DISCOVERY=dhcpv6`, `MM_WAN_MODEL=dhcpv6-pd`)
still passes its full smoketest with the reordered startup. What is *not* observed is the original hang
against a real line — minuteman has never run against one — but it follows from the retransmission
constants above rather than from inference about the network.

## 4. Minor / acceptable for a home CPE

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
- Dynamic-B4 change detection is polling (`internal/softwirectl`'s B4 poll, ~30s), not event-driven. A netlink
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
- `internal/wanextend` re-advertises the shared WAN prefix to the LAN with RFC 4861 §6.2.1's *default*
  lifetimes (30 days valid / 7 days preferred, `ra.go`'s `validLifetime`/`preferredLifetime`) because
  `DiscoverPrefix`/`WatchChanges` read the prefix back from the kernel's address list, and
  `pkg/netlink`'s `parseIfAddrMsg` doesn't decode `IFA_CACHEINFO` — so the WAN RA's actual remaining
  lifetimes are unknown to it. The NTT East IPoE spec's 光ネクスト 編 (§2.4.2.1.2) says the network's RA *may* carry
  Preferred Lifetime = 0, so this is reachable in the target deployment, not just in theory: minuteman
  would advertise a 7-day preferred lifetime for a prefix the network has already deprecated, telling LAN
  clients to keep sourcing from an address the network no longer prefers (RFC 4862 §5.5.4 makes
  deprecation the sender's signal to stop). The fix is to decode `IFA_CACHEINFO` in `parseIfAddrMsg`,
  carry the remaining lifetimes on the discovered prefix, and pass them into the RA config — the same
  values the RFC 9096 L-15/L-16 item above needs for the DHCPv6-PD side, so the two share the plumbing.
- The WAN-side RA's M/O flags (RFC 4861 §4.2) are never consulted: `pkg/routeradvert`'s codec is
  Marshal-only (it only detects that a Router Solicitation *arrived*, `isRouterSolicitation`), inbound
  RAs are left entirely to the kernel, and which LAN provisioning model runs is the operator's
  `-dhcpv6-pd`-vs-`-ndproxy` choice. No protocol requirement is broken, but the network signals the model
  minuteman currently has to be told, so this is the one piece of per-deployment configuration that AFTR
  discovery's own design goal (no per-VNE config) would say should be derived. The carrier spec's
  光ネクスト 編 (§2.4.2.1.2) makes the mapping explicit — on M=1 it 推奨s (recommends) DHCPv6-PD, and it
  names the RA's own 64-bit prefix as the *alternative* source of a usable address, which is precisely
  minuteman's `-ndproxy` model. So on that tier M discriminates the two, and deriving the model would
  remove the flag. Scope, though: the 光クロス and 光25G 編 are PD-only, so there the flag has nothing to
  choose between, and §3's Information-Request problem has to be settled first — on those tiers minuteman
  doesn't get far enough to care what an RA said. Deriving anything from an RA means decoding inbound RAs
  on the WAN, which nothing does today; the same receiver would supply the PIO lifetimes the
  `internal/wanextend` item above needs, so the two share the plumbing.
- RA MTU option (RFC 4861 §4.6.4) isn't advertised.
- MLD (RFC 3810) is left entirely to the kernel — minuteman forwards no IPv6 multicast of its own. Fine
  for a home gateway; would need revisiting for a router expected to do multicast routing.
- RFC 4389 proxy-loop detection is a documented non-goal of `pkg/ndproxy`; fine while WAN and LAN
  can't be accidentally bridged, worth revisiting otherwise.
- ICMP error quotes are fixed-size: the ICMPv6 Packet Too Big quotes only the invoking IPv6 header +
  8 bytes, where RFC 4443 asks for as much as fits in the minimum MTU. Enough for every real PMTUD
  consumer (ports/flow are within the 8 bytes); a full quote would need variable-length reply
  construction in XDP.
