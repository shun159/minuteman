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
| **6333** | Dual-Stack Lite Broadband Deployments Following IPv4 Exhaustion | ◐ | B4 element: XDP encap/decap datapath, MTU/PMTUD handling. Gaps: §5.3 softwire fragmentation (not done), §5.7 well-known B4 address 192.0.0.2 (unused). See backlog #1, #4. |
| **7785** | Recommendations for Prefix Binding in the Context of Softwire Dual-Stack Lite | ◐ | Basis for **dynamic B4**: on a WAN (B4) address change minuteman re-selects the source and hard-switches. §4 Rec 3 (AFTR migrates NAT state to the new B4) is relied on when the AFTR provides it, else flows break. §4 Rec 4 (PCP ANNOUNCE) ✗ — minuteman has no PCP. |
| **2473** | Generic Packet Tunneling in IPv6 | ○ | DS-Lite uses `nexthdr = IPPROTO_IPIP` directly (no encapsulation-limit option). Reactive ICMPv6-error → ICMPv4 relay (§8) is ✗ (backlog #5). |

## WAN provisioning & AFTR discovery

| RFC | Title | Support | Notes |
|-----|-------|:---:|-------|
| **3736** | Stateless DHCP Service for IPv6 | ✅ | Information-Request used to discover the AFTR-Name / DNS servers (`pkg/dhcpv6`). |
| **3315** | Dynamic Host Configuration Protocol for IPv6 (DHCPv6) | ✅ | Base client machinery (`pkg/dhcpv6`): retransmission timing (§5.5, §14), message validation, DUID. *Obsoleted by RFC 9915 — the code is written against 3315's structure and section numbers.* |
| **9915** | Dynamic Host Configuration Protocol for IPv6 (DHCPv6) — STD 102, obsoletes 8415 | ◐ | Current consolidated DHCPv6. Used for the refresh model: Information Refresh Time (§21.23) / Refreshing Configuration Information (§18.2.12), driving periodic AFTR re-discovery. Note: 9915 defines **no** link/address-change re-discovery trigger — that is RFC 7785's concern (see backlog #2 for the §14.2 T1/T2 gap). |
| **4242** | Information Refresh Time Option for DHCPv6 | ✅ | The refresh-interval hint that paces periodic AFTR re-discovery. |
| **6334** | DHCPv6 Option for Dual-Stack Lite (`OPTION_AFTR_NAME`) | ✅ | Decoded and resolved to the AFTR address (`pkg/aftrdiscovery`). |
| **1035** | Domain Names — Implementation and Specification | ○ | Wire-format decode of the AFTR-Name (compression pointers rejected, per RFC 3315 §8). |
| **3646** | DNS Configuration Options for DHCPv6 | ✅ | DNS servers (§3) parsed from the Reply, used for name resolution and `-dns-proxy` defaults. |
| **6724** | Default Address Selection for IPv6 | ✅ | **Dynamic B4** delegates source-address selection to the kernel via an `RTM_GETROUTE`/`RTA_PREFSRC` query — deprecated-avoidance, scope, longest-match all inherited rather than reimplemented. |

## DHCPv6 Prefix Delegation (`-dhcpv6-pd`)

| RFC | Title | Support | Notes |
|-----|-------|:---:|-------|
| **3633** | IPv6 Prefix Options for DHCP version 6 | ✅ | IA_PD / IAPREFIX acquire + Renew/Rebind maintenance (`pkg/prefixdelegation`). T1/T2 = 0 handling is a gap — see backlog #2 (RFC 9915 §14.2). |

## LAN-facing services

| RFC | Title | Support | Notes |
|-----|-------|:---:|-------|
| **4861** | Neighbor Discovery for IPv6 | ◐ | CPE subset only: sending Router Advertisements (§6.2, §6.2.5 graceful shutdown) and Router Solicitations (§6.1.2, §6.3.7). Full NDP message set ✗; RA MTU option (§4.6.4) ✗ (backlog). `pkg/routeradvert`. |
| **8106** | IPv6 Router Advertisement Options for DNS Configuration | ◐ | RDNSS advertised — but only while `-dns-proxy` binds a resolver to advertise (backlog: proxy-less case). |
| **4389** | Neighbor Discovery Proxies (ND Proxy) | ◐ | `-ndproxy`: active-verify proxying of WAN-side NS/NA for LAN hosts (`pkg/ndproxy`). Non-goals: cross-link DAD proxy, RA/Redirect proxy, proxy-loop detection. |
| **2131** | Dynamic Host Configuration Protocol (DHCPv4) | ◐ | `-dhcpv4` server, directly-attached single subnet per interface (`pkg/dhcpv4`). No BOOTP relay (§giaddr rejected), no shared networks, no restart persistence. DHCPREQUEST substates per §4.3.2, renewal timers per §4.4.5. |
| **2132** | DHCP Options and BOOTP Vendor Extensions | ✅ | Option TLV codec incl. Interface MTU (§5.1) for the DS-Lite-adjusted MTU. |
| **3396** | Encoding Long Options in DHCPv4 | ✅ | Values past 255 bytes split across repeated option instances. |
| **7084** | Basic Requirements for IPv6 Customer Edge Routers | ◐ | Aspirational compliance target. §L-4 (RDNSS to SLAAC clients) drives the RA RDNSS option; several requirements remain open (see backlog). |
| **6333** (§ B4 SHOULD) | DNS proxy | ✅ | `-dns-proxy`: opaque UDP/TCP relay to upstream resolvers, bypassing the softwire (`pkg/dnsproxy`). |
| **7766** | DNS Transport over TCP — Implementation Requirements | ✅ | TCP DNS relayed as a byte stream, so query pipelining (§6.2.1) works for free. |

## ICMP & IPv4 forwarding in the datapath

| RFC | Title | Support | Notes |
|-----|-------|:---:|-------|
| **4443** | ICMPv6 for IPv6 | ◐ | In-datapath Packet Too Big origination with per-CPU token-bucket rate-limiting (§2.4(f)). Quote is fixed-size (invoking header + 8 bytes), not "as much as fits in the min MTU". |
| **791** | Internet Protocol | ○ | Minimum IPv4 MTU (68 B) as the DHCPv4 Interface-MTU floor. |
| **1812** | Requirements for IP Version 4 Routers | ✗ | §5.3.1 inner-TTL Time Exceeded from the B4 is a known gap (backlog #4). |
| **7335** | IPv4 Service Continuity Prefix | ✗ | The 192.0.0.0/29 realm / 192.0.0.2 B4 address is not yet used (backlog #4). |

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
