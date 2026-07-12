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

Stage (a) — safe live switching + the re-discovery loop itself:
- Replace the single `b4_config_map[0]` with a small fixed-slot `next_hops` array (value:
  `{valid, aftr_addr, b4_addr}` — MACs/egress deliberately *not* frozen in; the per-packet
  `lookup_aftr_nexthop` FIB resolution stays) plus a single-`__u32` `active_nh` index. Encap reads
  `next_hops[active_nh]`; decap's `is_expected_dslite_peer` accepts any `valid` slot (2 fixed slots
  suffice). This indirection is required for *any* live switch, draining or not:
  `bpf_map_update_elem` on an ARRAY map copies the new value into the element **in place**
  (`array_map_update_elem` → `copy_map_value`, `kernel/bpf/arraymap.c` — verified against mainline;
  no RCU replacement without `BPF_F_LOCK`), so overwriting the live `b4_config` mid-traffic can yield
  a torn half-old/half-new read. Write-new-slot-then-flip-one-word-index is the safe idiom.
- `cmd/minuteman` grows the re-discovery loop: consume the refresh intervals
  `aftrdiscovery.Result`/`hb46pp.Result` already report (echoing `hb46pp` `Token` back), and watch
  the WAN address (`internal/wanextend.WatchChanges`'s shape). Policy: a re-discovery whose result
  still contains the current AFTR is a **no-op** (DNS round-robin must not cause churn); a
  WAN-address change is a hard switch — the AFTR's NAT state is keyed to the B4 address, so
  in-flight flows are unrecoverable regardless and draining would be pointless; an AFTR-only change
  is a hard switch in stage (a), a drain in stage (b).
- The netns rig needs a second AFTR plus a record/provisioning swap mechanism to exercise this.

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

## 7. Minor / acceptable for a home CPE

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
