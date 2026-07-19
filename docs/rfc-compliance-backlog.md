# RFC compliance backlog

minuteman works as a DS-Lite B4 (verified end-to-end against the netns rig — see
`test/netns/README.md`), but measured strictly against the base RFC 7084 (IPv6 CE Router Requirements)
and RFC 6333, these gaps remain. Ordered by real-world impact, highest first. Last checked against the
codebase 2026-07-18. (RFC 7084's own updates — RFC 9096 renumbering reaction and RFC 9818 LAN-side
prefix delegation — are not targeted; see the RFC 9096 item in §6 and `docs/supported-rfcs.md`.)

Softwire fragmentation (RFC 6333 §5.3) is now *partially* addressed by the `internal/slowpath` companion
`ip6tnl` — the reassembly half is RFC-conformant, the fragmentation half is not; it remains a real gap,
tracked as §4 below (see also `CLAUDE.md`).

## 1. DHCPv6-PD takes the server's T1/T2 literally, including 0 — RFC 3633 §9 / RFC 9915 §14.2

`pkg/prefixdelegation/maintain.go`'s `Maintain` sleeps until `AcquiredAt + T1` with the
server-supplied T1 used as-is, and nothing anywhere derives client-side timers: a delegating router
that sets T1=T2=0 is delegating the renewal timing to the requesting router (RFC 3633 §9), which
RFC 9915 §14.2 ("Client Behavior when T1 and/or T2 Are 0") then requires to choose its own times —
explicitly *not immediately*, and avoiding message storms (0.5 × / 0.8 × the shortest preferred
lifetime, the ratio DHCPv6 recommends for server-set timers, is the usual choice). Taken literally,
T1=0 makes `sleepUntil` return immediately, so every successful Renew flows straight into the next — a
busy Renew loop hammering the delegating server for as long as it keeps answering (each iteration is
one exchange RTT, no sleep at all). T1 > T2 (RFC 9915 §21.21: a requesting router discards such an
IA_PD) isn't sanity-checked either, and `tryRenew`'s deadline of `AcquiredAt + T2` goes similarly
wrong when T2=0.

**Effect:** real delegating routers do send T1=T2=0; against one, minuteman becomes a renew storm.
Never exercised by the netns rig (its Kea is configured with renew-timer 1800).

**Fix:** when T1 and/or T2 is 0, derive them from the shortest preferred lifetime per RFC 9915 §14.2
(with a sane floor, and no immediate transmit); discard IA_PDs carrying 0 < T2 < T1.

## 2. Every Renew restarts the LAN RA workers through their shutdown path — RFC 4861 §6.2.5 misapplied

`internal/lanprefix.RAManager.Sync` deliberately restarts every RA worker on every lease change (to
pick up refreshed lifetimes — its comment claims restarting has no churn equivalent to `Reconcile`'s),
but "restart" is cancel-then-start, and `pkg/routeradvert.Serve`'s cancellation path sends the RFC
4861 §6.2.5 graceful-shutdown RA: RouterLifetime=0, and (since RDNSS lifetime is tied to
RouterLifetime in `buildRA`) RDNSS Lifetime=0 with it. So on every T1 Renew, every LAN client is told
"this router is going away and stop using its DNS server", then re-told everything a moment later by
the new worker's immediate first RA. The final RA is exactly the churn the comment says doesn't exist.

**Effect:** periodic (every T1 interval) transient default-route withdrawal plus RDNSS invalidation on
all LAN clients — a brief routing/resolver flap per renewal, worse on hosts that honour RDNSS
lifetimes promptly. `internal/wanextend`'s raManager has the same shutdown-RA-on-restart shape but
only restarts on an actual WAN prefix change, where deprecating the old state is at least arguably
right.

**Fix direction:** let `routeradvert.Serve` take lifetime/config updates in place (channel or atomic
pointer consulted per send) so a Renew never restarts the worker; or plumb a "restarting, not shutting
down" signal that suppresses the final RA.

## 3. Tunnel-originated ICMPv4: decap-side Time Exceeded, and the B4 well-known address is unused — RFC 1812 §5.3.1, RFC 6333 §5.7 + RFC 7335

Two related gaps around ICMPv4 the B4 itself must originate:

- **Inner TTL expiry — outbound now handled, inbound still not** (RFC 1812 §5.3.1 MUST).
  `xdp_dslite_encap` XDP_PASSes an inner TTL≤1 packet to the kernel; since the softwire fragmentation
  slow path added the companion `ip6tnl` and an IPv4 default route through it (`internal/slowpath`),
  the kernel now has a route to forward toward and answers **ICMPv4 Time Exceeded** for the expiry
  (verified against the netns rig — a LAN `ping -t 1` gets Time Exceeded from the CPE, where it used to
  get Destination Unreachable). What remains is the **decap** side: `xdp_dslite_decap` XDP_PASSes the
  *still-encapsulated* packet on an inner-TTL check that runs pre-decap, but the companion ip6tnl
  decapsulates it (its outer header is `nexthdr == IPPROTO_IPIP`) and then the inner TTL≤1 packet is
  dropped by the kernel's own forwarding without a softwire-re-encapsulated Time Exceeded going back to
  the original IPv4 sender, so inbound traceroute still gets no reply at the B4 hop.
- **192.0.0.2 unused** (RFC 6333 §5.7 + RFC 7335): the B4's tunnel-side ICMP (today only its ICMPv4
  Fragmentation-Needed replies) is sourced from the LAN gateway's private IPv4 instead of the
  well-known B4 address.

**Effect:** inbound traceroute and PMTUD-adjacent tooling still misbehave at the B4 hop; reachability
itself unaffected.

## 4. Softwire fragmentation is inner-IPv4, not RFC-canonical outer-IPv6 — RFC 6333 §5.3 (errata 5847) / RFC 2473 §7.2(b)

`internal/slowpath`'s companion `ip6tnl` handles the *reassembly* half correctly (fragmented softwire IPv6
is `XDP_PASS`ed, the kernel reassembles before the ip6tnl decapsulates — exactly §5.3's "reassembly MUST
happen before decapsulation"). The *fragmentation* half is not RFC-canonical. RFC 6333 §5.3 (with the
original "The inner IPv4 packet MUST NOT be fragmented; fragmentation MUST happen after encapsulation",
and errata 5847 pointing at RFC 2473 §7.2(b), ignoring the DF bit) requires the B4 to fragment the *outer
IPv6* tunnel packet after encapsulation. Linux's `ip6tnl` cannot do that — it either PMTUD-signals (ICMPv4
Fragmentation-Needed) or, with the tunnel MTU set to WAN−40 as here, lets the kernel's IPv4 forwarding
fragment the **inner IPv4** before encapsulation. So minuteman's encap slow path fragments the inner IPv4
for a **non-DF** oversized packet (which §5.3 says MUST NOT be done, though it preserves reachability) and
sends ICMPv4 Fragmentation-Needed for a **DF** one (which §5.3 says should instead be tunnel-fragmented,
ignoring DF).

**Effect:** in practice benign — minuteman advertises a reduced LAN MTU (DHCPv4 option 26 = WAN−40), so
well-behaved clients never emit an oversized inner packet, and the slow path is only a fallback for clients
that ignore it (non-DF: fragmented and delivered; DF: told to reduce via PMTUD). But it is not §5.3-conformant
on the fragmentation side, and true conformance needs a custom outer-IPv6 fragmentation/reassembly path
(in XDP or a userspace raw socket) rather than the kernel tunnel — the "substantial undertaking" this item
originally called out.

## 5. Tunnel ICMPv6 relay — RFC 2473 §8

No reactive translation exists of an ICMPv6 error about the softwire packet itself (e.g. a Packet Too Big
or Time Exceeded from an intermediate IPv6 router on the B4↔AFTR path) into an ICMPv4 error toward the
original IPv4 sender. The encap path's own proactive `bpf_check_mtu`-based PtB only covers the
locally-known egress MTU, not a smaller MTU somewhere further along the IPv6 path.

## 6. Minor / acceptable for a home CPE

- During an AFTR graceful migration's drain window the softwire slow-path companion device is repointed at
  the *new* AFTR at cutover, so a *draining* flow's own fragments (a rare corner: fragmentation overlapping
  a migration) fall to the kernel with the old remote and are dropped until the flow finishes — the fast
  path's dual-AFTR decap is unaffected.

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
