# internal/

CLI glue and CPE **policy** — the decisions that are minuteman's rather than an RFC's, plus the
kernel-object lifecycles that support the datapath. The reusable protocol/wire-format code
lives in `pkg/` and knows nothing about this layer; these packages call into it, never the
reverse.

| Package | Role | Paired `pkg/` |
| --- | --- | --- |
| [`cliconfig`](cliconfig/) | parses flag *values* (`-lan`, `-dns-server`, `-wan-dst-mac`, `-tcp-mss-clamp`) into typed config | — |
| [`lanprefix`](lanprefix/) | DHCPv6-PD policy: carve one `/64` per LAN interface, assign it, advertise it (On-Link **set**) | `prefixdelegation`, `routeradvert` |
| [`wanextend`](wanextend/) | NDProxy policy: learn the shared WAN `/64`, advertise it (On-Link **cleared**), maintain `/128` host routes | `ndproxy`, `routeradvert` |
| [`slowpath`](slowpath/) | the companion `ip6tnl` for softwire reassembly + the fragmentation fallback | `netlink` |
| [`fragpath`](fragpath/) | the companion veth pairs the in-XDP softwire fragmenter bounces clones through | `netlink`, `datapath` |
| [`dhcpv6client`](dhcpv6client/) | the WAN's DHCPv6 client: a molecule process owning `[link-local%iface]:546`, running `pkg/dhcpv6` exchanges one at a time (the `dhcpv6.Exchanger` of `aftrdiscovery` and `prefixdelegation`) | `dhcpv6` |
| [`dnsproxy`](dnsproxy/) | RFC 6333's B4 SHOULD: an opaque DNS byte relay over native IPv6 — a molecule supervision tree of UDP and TCP listeners | — |
| [`softwirectl`](softwirectl/) | the single owner of the live softwire endpoints: AFTR re-discovery and flow-preserving migration, B4 re-selection — a molecule supervision tree around a pure genstatem | `datapath` |

`lanprefix` and `wanextend` are alternatives, not layers: they implement the two WAN
provisioning models an ISP might offer, and `-dhcpv6-pd`/`-ndproxy` are mutually exclusive.
`slowpath` and `fragpath` both exist for RFC 6333 §5.3 — `fragpath` carries the conformant
in-XDP outer-IPv6 fragmentation, `slowpath` the inbound reassembly plus whatever the
fragmenter's guards reject.

Each package's README covers its own rationale; `CLAUDE.md`'s Architecture section is the
cross-cutting view.
