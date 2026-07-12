# RFC compliance backlog

minuteman works as a DS-Lite B4 (verified end-to-end against the netns rig — see
`test/netns/README.md`), but measured strictly against RFC 7084 (IPv6 CE Router Requirements) and
RFC 6333, these gaps remain. Ordered by real-world impact, highest first. Last checked against the
codebase 2026-07-12.

## 1. RDNSS-in-RA — RFC 8106 + RFC 7084 §L-4 (highest impact)

`pkg/routeradvert/options.go` emits only a Prefix Information Option (type 3) and Source Link-Layer
Address Option (type 1) — no RDNSS (type 25). `pkg/dnsproxy` only listens on each `-lan` interface's
*IPv4* gateway address (`cmd/minuteman/main.go`'s `runDNSProxy`, via `spec.GatewayIP`, which is IPv4-only).

**Effect:** an IPv6-only SLAAC LAN client gets an address and a default route from RA, but no DNS server
at all — RFC 7084 §L-4 requires either RDNSS in RA or LAN-side DHCPv6 to supply one.

**Fix:** add an RDNSS option to `pkg/routeradvert` (pointing at the CPE's own LAN IPv6 address) and have
`pkg/dnsproxy` also listen on that address, not just the IPv4 gateway.

## 2. Softwire fragmentation — RFC 6333 §5.3 (MUST)

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

## 3. B4 well-known address — RFC 6333 §5.7 + RFC 7335

`192.0.0.2` (the B4's well-known IPv4 address for tunnel-originated ICMP) is unused anywhere in the
codebase. The B4's own tunnel-side ICMP (its ICMPv4 Fragmentation-Needed replies) is sourced from the LAN
gateway's private IPv4 instead.

**Effect:** medium/low — affects the correctness of traceroute and third-party PMTUD tooling observing
the tunnel from outside, not reachability itself.

## 4. Tunnel ICMPv6 relay — RFC 2473 §8

No reactive translation exists of an ICMPv6 error about the softwire packet itself (e.g. a Packet Too Big
or Time Exceeded from an intermediate IPv6 router on the B4↔AFTR path) into an ICMPv4 error toward the
original IPv4 sender. The encap path's own proactive `bpf_check_mtu`-based PtB only covers the
locally-known egress MTU, not a smaller MTU somewhere further along the IPv6 path.

## 5. AFTR periodic re-discovery — RFC 4242, RFC 3315 WAN-change trigger

Already tracked in `CLAUDE.md`'s "Not yet implemented": `cmd/minuteman` discovers the AFTR once at
startup and never re-runs discovery, doesn't watch the refresh interval either package reports, and
doesn't watch for the WAN address changing. Applying a *changed* AFTR to the live datapath safely (today
`SetB4Config` is only ever called once, before the datapath is considered "up") without disrupting
in-flight softwire traffic is the harder part of implementing this.

## 6. Minor / acceptable for a home CPE

- RA MTU option (RFC 4861 §4.6.4) isn't advertised.
- MLD (RFC 3810) is left entirely to the kernel — minuteman forwards no IPv6 multicast of its own. Fine
  for a home gateway; would need revisiting for a router expected to do multicast routing.

---

The native-IPv6 forwarding fastpath itself (transit IPv6 routed in XDP instead of falling to the kernel
slow path) is implemented — see `CLAUDE.md`'s Architecture section, `handle_ipv6_forward`.
