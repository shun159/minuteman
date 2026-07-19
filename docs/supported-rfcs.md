# Supported RFCs

A human-readable map of the standards minuteman implements, grouped by function.
For *gaps* in an otherwise-supported area (and the priority order for closing
them), see [`rfc-compliance-backlog.md`](./rfc-compliance-backlog.md); this file
is the "what works" side of that same picture.

**Support levels**

| Mark | Meaning |
|------|---------|
| ✅ | Implemented — the behavior the RFC defines is provided (minor, documented gaps may remain). |
| ◐ | Partial — only a named subset of the RFC is implemented; the sections in scope are listed. |
| ○ | Referenced — used as a constraint, constant, or design rationale, not implemented as a protocol. |
| ✗ | Not implemented — a known gap or explicit non-goal; see the backlog. |

Non-RFC specs also implemented: **HB46PP / JAIPA v6mig-1** (the HTTP-Based IPv4-over-IPv6
Provisioning Protocol many Japanese VNEs use instead of the DHCPv6 AFTR-Name — `pkg/hb46pp`).

---

## DS-Lite softwire (the core)

| RFC | Title | Support | Notes |
|-----|-------|:---:|-------|
| **6333** | Dual-Stack Lite Broadband Deployments Following IPv4 Exhaustion | ◐ | B4 element: XDP encap/decap datapath, MTU/PMTUD handling. §5.3 fragmentation is only *partially* met via a kernel companion `ip6tnl` (`internal/slowpath`): the reassembly half is conformant (kernel reassembles a fragmented softwire before the ip6tnl decaps), but the fragmentation half is not — the kernel tunnel fragments the **inner IPv4** (which §5.3/errata 5847 says MUST NOT happen) for non-DF and PMTUD-signals for DF, rather than fragmenting the **outer IPv6**. Gaps: §5.3 outer fragmentation (backlog #4), §5.7 well-known B4 address 192.0.0.2 (backlog #3). |
| **7785** | Recommendations for Prefix Binding in the Context of Softwire Dual-Stack Lite | ◐ | Basis for **dynamic B4**: on a WAN (B4) address change minuteman re-selects the source and hard-switches. §4 Rec 3 (AFTR migrates NAT state to the new B4) is relied on when the AFTR provides it, else flows break. §4 Rec 4 (PCP ANNOUNCE) ✗ — minuteman has no PCP. |
| **2473** | Generic Packet Tunneling in IPv6 | ○ | DS-Lite uses `nexthdr = IPPROTO_IPIP` directly (no encapsulation-limit option). Reactive ICMPv6-error → ICMPv4 relay (§8) is ✗ (backlog #5). |

## WAN provisioning & AFTR discovery

| RFC | Title | Support | Notes |
|-----|-------|:---:|-------|
| **3736** | Stateless DHCP Service for IPv6 | ✅ | Information-Request used to discover the AFTR-Name / DNS servers (`pkg/dhcpv6`). |
| **3315** | Dynamic Host Configuration Protocol for IPv6 (DHCPv6) | ◐ | A 3315-era **client subset** only (`pkg/dhcpv6`): the Information-Request and IA_PD exchanges minuteman needs, with retransmission timing (§5.5, §14), message validation, and DUID — not a full DHCPv6 implementation. *Obsoletion chain: RFC 3315 → RFC 8415 → RFC 9915 (STD 102); the current normative reference is RFC 9915, though the code is written against 3315's structure and section numbers.* |
| **9915** | Dynamic Host Configuration Protocol for IPv6 (DHCPv6) — STD 102, obsoletes 8415 | ◐ | Current consolidated DHCPv6. Used for the refresh model: Information Refresh Time (§21.23) / Refreshing Configuration Information (§18.2.12), driving periodic AFTR re-discovery. Note: 9915 defines **no** link/address-change re-discovery trigger — that is RFC 7785's concern (see backlog #1 for the §14.2 T1/T2 gap). |
| **4242** | Information Refresh Time Option for DHCPv6 | ✅ | The refresh-interval hint that paces periodic AFTR re-discovery. |
| **6334** | DHCPv6 Option for Dual-Stack Lite (`OPTION_AFTR_NAME`) | ✅ | Decoded and resolved to the AFTR address (`pkg/aftrdiscovery`). |
| **1035** | Domain Names — Implementation and Specification | ○ | Wire-format decode of the AFTR-Name (compression pointers rejected, per RFC 3315 §8). |
| **3646** | DNS Configuration Options for DHCPv6 | ✅ | DNS servers (§3) parsed from the Reply, used for name resolution and `-dns-proxy` defaults. |
| **6724** | Default Address Selection for IPv6 | ✅ | **Dynamic B4** delegates source-address selection to the kernel via an `RTM_GETROUTE`/`RTA_PREFSRC` query — deprecated-avoidance, scope, longest-match all inherited rather than reimplemented. |

## DHCPv6 Prefix Delegation (`-dhcpv6-pd`)

| RFC | Title | Support | Notes |
|-----|-------|:---:|-------|
| **3633** | IPv6 Prefix Options for DHCP version 6 | ◐ | IA_PD / IAPREFIX acquire + Renew/Rebind maintenance (`pkg/prefixdelegation`). Not merely a minor gap: T1/T2 = 0 is taken literally, which becomes a renew storm against a server that sends it — see backlog #1 (needs RFC 9915 §14.2 client-timer behavior + invalid-T1/T2 handling). |

## LAN-facing services

| RFC | Title | Support | Notes |
|-----|-------|:---:|-------|
| **4861** | Neighbor Discovery for IPv6 | ◐ | CPE subset only: sending Router Advertisements (§6.2, §6.2.5 graceful shutdown) and Router Solicitations (§6.1.2, §6.3.7). Full NDP message set ✗; RA MTU option (§4.6.4) ✗ (backlog). `pkg/routeradvert`. |
| **8106** | IPv6 Router Advertisement Options for DNS Configuration | ◐ | RDNSS advertised — but only while `-dns-proxy` binds a resolver to advertise (backlog: proxy-less case). |
| **4389** | Neighbor Discovery Proxies (ND Proxy) | ◐ | `-ndproxy`: active-verify proxying of WAN-side NS/NA for LAN hosts (`pkg/ndproxy`). Non-goals: cross-link DAD proxy, RA/Redirect proxy, proxy-loop detection. |
| **2131** | Dynamic Host Configuration Protocol (DHCPv4) | ◐ | `-dhcpv4` server, directly-attached single subnet per interface (`pkg/dhcpv4`). No BOOTP relay (§giaddr rejected), no shared networks, no restart persistence. DHCPREQUEST substates per §4.3.2, renewal timers per §4.4.5. |
| **2132** | DHCP Options and BOOTP Vendor Extensions | ✅ | Option TLV codec incl. Interface MTU (§5.1) for the DS-Lite-adjusted MTU. |
| **3396** | Encoding Long Options in DHCPv4 | ✅ | Values past 255 bytes split across repeated option instances. |
| **7084** | Basic Requirements for IPv6 Customer Edge Routers | ◐ | Aspirational compliance target for the *base* document. §L-11 (DNS via RA, referencing RFC 6106/8106) drives the RA RDNSS option — but minuteman advertises **RDNSS only**, not the DNSSL option L-11 also calls for. Several base requirements remain open (see backlog). The updates below (RFC 9096, RFC 9818) are **not** targeted. |
| **9096** | Improving the Reaction of Customer Edge Routers to IPv6 Renumbering Events (updates 7084) | ✗ | Not implemented. Adds WPD-9/WPD-10 (WAN: don't auto-RELEASE on restart; stable WAN IAID) and L-13(replaced)/L-15/L-16 (LAN: signal stale config; cap LAN SLAAC/DHCPv6 lifetimes to the WAN prefix's remaining lifetime). Newly relevant given dynamic B4 handles WAN renumbering — see backlog. |
| **9818** | IPv6 Prefix Delegation on the Local Area Network (updates 7084) | ✗ | Out of scope. Adds LPD-1..LPD-10 (running DHCPv6-PD on the *LAN* side to delegate sub-prefixes to downstream routers). minuteman is a single-tier CPE: LAN hosts SLAAC from one carved /64, no downstream delegation. |
| **6333** (§ B4 SHOULD) | DNS proxy | ✅ | `-dns-proxy`: opaque UDP/TCP relay to upstream resolvers, bypassing the softwire (`pkg/dnsproxy`). |
| **7766** | DNS Transport over TCP — Implementation Requirements | ✅ | TCP DNS relayed as a byte stream, so query pipelining (§6.2.1) works for free. |

## ICMP & IPv4 forwarding in the datapath

| RFC | Title | Support | Notes |
|-----|-------|:---:|-------|
| **4443** | ICMPv6 for IPv6 | ◐ | In-datapath Packet Too Big origination with per-CPU token-bucket rate-limiting (§2.4(f)). Quote is fixed-size (invoking header + 8 bytes), not "as much as fits in the min MTU". |
| **791** | Internet Protocol | ○ | Minimum IPv4 MTU (68 B) as the DHCPv4 Interface-MTU floor. |
| **1812** | Requirements for IP Version 4 Routers | ◐ | §5.3.1 inner-TTL Time Exceeded: the outbound (encap) direction is now answered by the kernel via the softwire slow path's IPv4 default route; the inbound (decap) direction is still a gap (backlog #3). |
| **7335** | IPv4 Service Continuity Prefix | ✗ | The 192.0.0.0/29 realm / 192.0.0.2 B4 address is not yet used (backlog #3). |

## Test rig / documentation conventions only

| RFC | Title | Where |
|-----|-------|-------|
| **5737** | IPv4 Address Blocks Reserved for Documentation | netns rig addressing. |
| **3849** | IPv6 Address Prefix Reserved for Documentation | netns rig addressing. |
| **4941** | Privacy Extensions for SLAAC in IPv6 | netns rig disables temp addresses for deterministic asserts. |
| **5952** | A Recommendation for IPv6 Address Text Representation | netns rig assertions. |

## Not implemented (non-goals / future work)

| RFC | Title | Status |
|-----|-------|--------|
| **3810** | Multicast Listener Discovery Version 2 (MLDv2) | ✗ Left entirely to the kernel; minuteman routes no IPv6 multicast of its own. Fine for a home gateway. |
| **6887 / 7648 / 7291** | Port Control Protocol + PCP proxy + DHCPv6 options for PCP | ✗ No PCP. Would be the path to DS-Lite inbound connectivity; also what RFC 7785 §4 Rec 4's PCP ANNOUNCE presupposes. |
| — | MAP-E / MAP-T / lw4o6 / 464xlat / ipip | ✗ HB46PP can advertise these; `pkg/hb46pp` preserves their parameters raw, but only DS-Lite is implemented. |

See [`rfc-compliance-backlog.md`](./rfc-compliance-backlog.md) for the prioritized gap list and the
specific code each gap points at.
