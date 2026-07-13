# RFC compliance backlog

minuteman works as a DS-Lite B4 (verified end-to-end against the netns rig — see
`test/netns/README.md`), but measured strictly against RFC 7084 (IPv6 CE Router Requirements) and
RFC 6333, these gaps remain. Ordered by real-world impact, highest first. Last checked against the
codebase 2026-07-12.

## 1. Softwire fragmentation — RFC 6333 §5.3 (MUST) (highest remaining impact)

`bpf/datapath.bpf.c`'s `xdp_dslite_encap` drops (rather than fragments) an oversized non-DF inner IPv4
packet (`STAT_MTU_DROP` → `XDP_DROP`). `xdp_dslite_decap` can't reassemble a fragmented softwire IPv6
packet either — `parse_l2_ipv6` doesn't walk the IPv6 fragment extension header, so `nexthdr == 44`
packets fall through to `XDP_PASS` with no reassembly behind that.

**Effect:** works in practice whenever the ISP's IPv6 path MTU is ≥1500 and LAN clients respect
DHCPv4-advertised MTU (option 26)/PMTUD, but is not RFC 6333 §5.3-compliant, which mandates fragmentation
support at the B4/AFTR when the IPv6 path can't be guaranteed ≥1540.

**Fix direction:** true in-XDP fragmentation/reassembly is a substantial undertaking; a cheaper first cut
is an `XDP_PASS` fallback to a kernel `ip6tnl` for the decap side specifically, letting the kernel
reassemble before minuteman ever sees the packet.

## 2. DHCPv6-PD takes the server's T1/T2 literally, including 0 — RFC 3633 §9 / RFC 8415 §18.2.4

`pkg/prefixdelegation/maintain.go`'s `Maintain` sleeps until `AcquiredAt + T1` with the
server-supplied T1 used as-is, and nothing anywhere derives client-side timers: a delegating router
that sets T1=T2=0 is delegating the renewal timing to the requesting router (RFC 3633 §9), which is
then supposed to pick its own (RFC 8415 §18.2.4 recommends T1 = 0.5 × and T2 = 0.8 × the shortest
preferred lifetime). Taken literally, T1=0 makes `sleepUntil` return immediately, so every successful
Renew flows straight into the next — a busy Renew loop hammering the delegating server for as long as
it keeps answering (each iteration is one exchange RTT, no sleep at all). T1 > T2 (RFC 8415: such an
IA_PD is invalid and must be ignored) isn't sanity-checked either, and `tryRenew`'s deadline of
`AcquiredAt + T2` goes similarly wrong when T2=0.

**Effect:** real delegating routers do send T1=T2=0; against one, minuteman becomes a renew storm.
Never exercised by the netns rig (its Kea is configured with renew-timer 1800).

**Fix:** when T1 and/or T2 is 0, derive them from the shortest preferred lifetime per RFC 8415
§18.2.4 (with a sane floor); discard IA_PDs carrying 0 < T2 < T1.

## 3. Every Renew restarts the LAN RA workers through their shutdown path — RFC 4861 §6.2.5 misapplied

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

## 4. Tunnel-originated ICMPv4: no Time Exceeded, and the B4 well-known address is unused — RFC 1812 §5.3.1, RFC 6333 §5.7 + RFC 7335

Two related gaps around ICMPv4 the B4 itself must originate:

- **Inner TTL expiry produces no Time Exceeded** (RFC 1812 §5.3.1 MUST). `xdp_dslite_encap` XDP_PASSes
  an inner TTL≤1 packet to the kernel, but a DS-Lite CPE kernel typically has no IPv4 default route,
  so the kernel answers Destination Unreachable instead — traceroute from a LAN client through the
  softwire terminates at the first hop with `!N`. `xdp_dslite_decap` XDP_PASSes the
  *still-encapsulated* packet (its TTL check is pre-decap), which the kernel can't parse past (no
  ip6tnl is bound to nexthdr 4), so inbound traceroute gets no reply at all at the B4 hop.
- **192.0.0.2 unused** (RFC 6333 §5.7 + RFC 7335): the B4's tunnel-side ICMP (today only its ICMPv4
  Fragmentation-Needed replies) is sourced from the LAN gateway's private IPv4 instead of the
  well-known B4 address.

**Effect:** traceroute and PMTUD-adjacent tooling misbehave in both directions at the B4 hop;
reachability itself unaffected.

## 5. Tunnel ICMPv6 relay — RFC 2473 §8

No reactive translation exists of an ICMPv6 error about the softwire packet itself (e.g. a Packet Too Big
or Time Exceeded from an intermediate IPv6 router on the B4↔AFTR path) into an ICMPv4 error toward the
original IPv4 sender. The encap path's own proactive `bpf_check_mtu`-based PtB only covers the
locally-known egress MTU, not a smaller MTU somewhere further along the IPv6 path.

## 6. AFTR periodic re-discovery — RFC 4242, RFC 3315 WAN-change trigger

Already tracked in `CLAUDE.md`'s "Not yet implemented": `cmd/minuteman` discovers the AFTR once at
startup and never re-runs discovery, doesn't watch the refresh interval either package reports, and
doesn't watch for the WAN address changing. Applying a *changed* AFTR to the live datapath safely (today
`SetB4Config` is only ever called once, before the datapath is considered "up") without disrupting
in-flight softwire traffic is the harder part of implementing this.

**Fix direction**:

Stage (a1) — safe live switching (DONE, merged): the single `b4_config_map[0]` is replaced with a
fixed-slot `next_hops` array (`{valid, b4_addr, aftr_addr}`) selected by a single-`__u32` `active_nh`
index; `SwitchAFTR` writes the inactive slot then flips the index (never mutating the slot in use),
and decap (`find_dslite_peer_nh`) accepts any valid slot. See `pkg/datapath/config.go`.

Stage (a2) — the re-discovery loop (DONE): `cmd/minuteman`'s `runAFTRRediscovery` re-runs discovery on
the refresh interval each result reports (RFC 4242 / HB46PP ttl), echoing the HB46PP `Token`, and calls
`SwitchAFTR` when the AFTR address changes (no-op when unchanged; keeps the current AFTR and retries
sooner on failure). Runs only when the AFTR was discovered (a static `-aftr` has no refresh). Each
periodic attempt is time-bounded, and DHCPv6 exchanges on the WAN are serialized by a per-interface lock
(`pkg/dhcpv6.lockWAN`) so this loop can't collide with DHCPv6-PD maintenance on the `:546` bind. Two
known limits carried here for follow-up:
  - **No WAN-address-change trigger.** RFC 3315 says re-discovery should also fire when the WAN address
    changes, and such a change is a hard switch (the AFTR's NAT state is keyed to the B4 address, so
    in-flight flows are unrecoverable regardless). This needs a **dynamic B4** first — today `-b4` is a
    static required flag, so there's no live WAN address to track or switch to. Dynamic B4 (discover
    the WAN interface's own global IPv6 and watch it, `internal/wanextend.WatchChanges`'s shape) is its
    own item and a prerequisite; the current static-`-b4` model is not viable for a real deployment
    where the WAN address is SLAAC/DHCPv6-assigned.
  - **AFTR-name round-robin causes a switch each refresh.** The no-op check compares a single resolved
    address (`aftrdiscovery` returns `addrs[0]`), not set membership, so a name with multiple AAAA
    records flips the AFTR each refresh. Benign at day-scale intervals; a proper fix exposes all
    resolved addresses and no-ops on membership.

Stage (b) — drain-window flow affinity, only for AFTR-only changes:
- On switch, open a bounded drain window (~30-60 min) and register *new* inner-IPv4 flows (5-tuple
  key; `BPF_NOEXIST` insert + re-lookup to settle the multi-RX-queue race) pointing at the new slot.
  A flow-table **miss** during the window means a pre-switch flow → old slot. Window end: drop the
  table, clear the old slot's `valid` (closing decap acceptance of the old AFTR). Inverting the
  tracking this way — new flows during the window only, not all flows always — keeps steady-state
  per-packet cost at zero and needs no GC daemon; the trade-off (flows outliving the window break)
  is already bounded by the old AFTR's own NAT idle timeouts, and it's extendable to always-on
  tracking + `last_seen_ns` GC if unbounded draining ever matters.
- Corners: portless/fragmented traffic degrades to a ports=0 key; a full flow table forwards
  unpinned via the active slot (never drops); plain `HASH`, not `LRU_HASH` (eviction would silently
  unpin live flows mid-stream). No PROG_ARRAY/tail-call dispatch — the action variants stay an
  inline switch — and the native-IPv6 fastpath is untouched (no AFTR involvement).

## 7. Dynamic B4 address — RFC 6333 (prerequisite for #6's WAN-change trigger)

`-b4` is a required *static* flag: the B4's own IPv6 softwire source address is fixed at startup. A real
CPE's WAN address is SLAAC- or DHCPv6-assigned and changes over time (renumbering, lease expiry,
reconnect); when it does, minuteman keeps encapsulating from a stale source and the softwire breaks with
no recovery short of a restart. This also blocks #6's WAN-address-change re-discovery trigger, which has
no live B4 to switch to.

**Fix direction:** make `-b4` optional — when omitted, discover the WAN interface's own global IPv6
address (the netlink address-listing already used by `internal/wanextend.DiscoverPrefix`) and use it as
the B4, then watch it (`internal/wanextend.WatchChanges`'s shape) and drive a hard `SwitchAFTR(newB4,
aftr)` when it changes (the datapath already switches both endpoints atomically). Keep `-b4` as an
explicit override. Needs care around which global address to pick when several are present, and around
sequencing against the AFTR re-discovery loop (a WAN change should also re-trigger AFTR discovery).

## 8. Minor / acceptable for a home CPE

- RDNSS is only advertised while `-dns-proxy` is on; with it off (the default), an IPv6-only SLAAC LAN
  client is DNS-less again (RFC 7084 §L-4). The proxy-less alternative — advertising the WAN-learned
  upstream resolvers directly in RDNSS — would cover the default configuration too.
- RA MTU option (RFC 4861 §4.6.4) isn't advertised.
- MLD (RFC 3810) is left entirely to the kernel — minuteman forwards no IPv6 multicast of its own. Fine
  for a home gateway; would need revisiting for a router expected to do multicast routing.
- RFC 4389 proxy-loop detection is a documented non-goal of `pkg/ndproxy`; fine while WAN and LAN
  can't be accidentally bridged, worth revisiting otherwise.
- ICMP error quotes are fixed-size: the ICMPv6 Packet Too Big quotes only the invoking IPv6 header +
  8 bytes, where RFC 4443 asks for as much as fits in the minimum MTU. Enough for every real PMTUD
  consumer (ports/flow are within the 8 bytes); a full quote would need variable-length reply
  construction in XDP.
