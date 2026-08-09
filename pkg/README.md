# pkg/

The reusable half of minuteman: the XDP datapath loader plus one package per protocol. These
know nothing about CPE policy — which `/64` a LAN interface should get, when to re-discover an
AFTR, what a confirmed neighbor implies for the routing table. That lives in
[`internal/`](../internal/), which calls into these.

| Package | Implements | Depends on |
| --- | --- | --- |
| [`datapath`](datapath/) | loads and drives the XDP/eBPF datapath — the only package touching `cilium/ebpf` or BPF map layouts | — |
| [`dhcpv6`](dhcpv6/) | generic DHCPv6 client: RFC 3736 stateless + RFC 3315 stateful exchanges | — |
| [`aftrdiscovery`](aftrdiscovery/) | RFC 6334 AFTR discovery (`OPTION_AFTR_NAME` → address) | `dhcpv6` |
| [`hb46pp`](hb46pp/) | HB46PP / v6mig-1 — the VNE-agnostic HTTP provisioning fallback | — |
| [`prefixdelegation`](prefixdelegation/) | RFC 3633 / 9915 prefix delegation, acquire **and** maintain | `dhcpv6` |
| [`routeradvert`](routeradvert/) | RFC 4861: sending RAs on the LAN, RSes on the WAN | — |
| [`ndproxy`](ndproxy/) | RFC 4389 Neighbor Discovery Proxy, actively verified | — |
| [`netlink`](netlink/) | hand-rolled `NETLINK_ROUTE` client — the only netlink wire code | — |
| [`dnsproxy`](dnsproxy/) | RFC 6333's B4 SHOULD: an opaque DNS byte relay over native IPv6 | — |
| [`dhcpv4`](dhcpv4/) | RFC 2131/2132 LAN-side DHCPv4 server | — |

## Conventions these packages share

**Stdlib and `x/sys/unix` only.** No DHCP library, no netlink library, no `x/net/icmp` — and no
sidecar processes. Constants the Go ecosystem doesn't export (`ICMP6_FILTER`, `IFLA_IPTUN_*`) are
vendored locally, the same way `bpf/uapi/linux/*.h` vendors what BTF-derived `vmlinux.h` lacks.

**Pure logic separated from I/O, so it can be unit-tested.** `ndproxy`'s `proxyState`, `dhcpv4`'s
`Pool` and `handle`, `prefixdelegation`'s `effectiveTimers`, `dhcpv6`'s retransmission formulas —
each takes an explicit `now` or plain values rather than reading a clock or a socket. Raw-socket
I/O and goroutine orchestration are covered by the netns rig instead (`test/netns/README.md`).

**Open synchronously, serve in the background.** `dnsproxy.Listen`/`Serve` and `dhcpv4.New`/`Serve`
both split binding from running, so a bind failure fails `cmd/minuteman`'s startup instead of
appearing later in a log line — which is what lets minuteman advertise a DNS server only once
something is really listening on it.

**Policy is reported, not enacted.** `aftrdiscovery` returns RFC 4242's refresh interval and
`hb46pp` returns a `RetryDelay` window; neither sleeps on it. The exception is
`prefixdelegation.Maintain`, and for a concrete reason: an unrenewed lease actually expires and
breaks LAN connectivity, where a stale discovery result is merely stale.

Each package's README covers its own rationale; `CLAUDE.md`'s Architecture section is the
cross-cutting view.
