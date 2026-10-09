# internal/dnsproxy

The DNS proxy RFC 6333 recommends a DS-Lite B4 run (the B4 SHOULD act as a DNS proxy for its LAN
clients): it listens on the LAN side and forwards each query verbatim to upstream servers
reachable **natively over IPv6**.

## Why a B4 wants this

A LAN client's DNS query is ordinary IPv4 traffic, and `xdp_dslite_encap` has no way to tell a
DNS packet from any other IPv4 packet. Without this proxy, every lookup takes the full softwire
round trip — encapsulated to the AFTR, through its NAT44, and back. With it, the query leaves the
CPE's own process on a plain IPv6 socket and **structurally bypasses the softwire**, which is
also why the upstreams must be natively reachable (typically the WAN's own DHCPv6
`OPTION_DNS_SERVERS`): an address only reachable *through* the softwire would defeat the point,
and on a typical IPv6-only DS-Lite WAN isn't reachable from the CPE's untunneled IPv4 routing
table at all.

## Opaque by design

This package is opaque to DNS itself. It relays whatever bytes it receives and whatever bytes
come back — **no message parsing, no caching, no rewriting of any kind**. A forwarding proxy, not
a resolver, matching the RFC's own framing.

It lives in `internal/` rather than `pkg/` because it is nothing but I/O, run as a
[molecule](https://github.com/shun159/molecule) supervision tree; `pkg/` keeps to the stdlib.

## The tree

```
dnsproxy (one_for_one)
├── udp <addr>:53   the UDP listener, a genserver; an Async per query in flight
├── tcp <addr>:53   a gentcpacceptor raw listener; a relay process per connection
└── ...             the same for each listen address
```

`Spec(Config)` builds it; `cmd/minuteman`'s `startDNSProxy` starts it. Every listener binds while
the tree starts, so the start **fails fast** — no upstreams configured, port 53 already in use —
and returns only once every socket is bound.

That matters more than it looks: `cmd/minuteman` advertises one of these addresses to LAN clients
as their DNS server (RFC 8106 RDNSS, via `routeradvert.Config.RDNSSAddr`) **only once the tree has
started**. A silent bind failure would otherwise leave every client pointed at a DNS server nothing
answers on — worse than advertising none.

A listen address that is IPv6 link-local carries a zone (`netip.Addr.Zone()`, set by
`routeradvert.LinkLocalAddr`) so the kernel binds it to the right interface — `fe80::/10` isn't
unique without it. Right after XDP attach bounces the LAN link, that address is briefly
DAD-tentative and binding it fails with `EADDRNOTAVAIL`; the UDP listener waits that out
(`bindRetries` × `bindRetryInterval`, ~10s), and its TCP sibling, started after it, then binds at
once. Any other bind error fails at once.

## UDP (`udp.go`)

The listener is a genserver owning a `genudp` socket. Each query it forwards in a
**`molecule.Async`** of its own, so one slow or unresponsive upstream never holds up the next
query; the answer comes back as the Async's `AsyncResult`, and the listener relays it to the client
through its socket. The listener itself stays pure: forwarding blocks, and it is the Async's.

The socket's active mode is the flow control: it is armed `N(maxInFlight)` (256) once the listener
owns it, and re-armed by one as each query's Async ends. Past that many queries in flight, queries
wait in the kernel, which drops them when its buffer fills — the client's resolver retries, as
for any lost datagram. The listener stopping cancels its Asyncs.

A query tries `Config.Upstreams` in order over a **fresh, one-shot connected UDP socket**, each
bounded by `udpQueryTimeout` (5s); connected, it takes datagrams from that upstream alone. The
socket is deliberately not pooled: DNS-over-UDP is a single datagram round trip anyway,
and a dedicated socket means a response can never be confused with a different concurrent
query's. If **every** upstream fails, the query is simply dropped — the client's own resolver
retries per its usual behavior, exactly as if this proxy weren't in the path.

## TCP (`tcp.go`)

A `gentcpacceptor` raw listener per address; `relay` handles each accepted connection in a process
of its own, relaying to the first upstream that accepts a connection (`tcpDialTimeout` = 5s each).

`relay` is a full **bidirectional byte-level `io.Copy` relay**, not a framer of individual
length-prefixed DNS-over-TCP messages. RFC 7766 §6.2.1 allows pipelining multiple queries on one
connection, which a byte relay handles for free without this package ever needing to find a
message boundary. Each direction half-closes (`CloseWrite`) when its copy finishes, and the relay
returns once both are done, or the process dies.

## Testing

`go test` runs the tree against loopback upstreams: UDP relaying, fallback past a silent
upstream, queries forwarded concurrently, TCP relaying, and the start failing on a taken port.
End to end, the netns rig's `MM_DNS_PROXY=1` toggle has `mm-host` `dig` a record through
minuteman's LAN gateway IP over **both UDP and TCP** and checks the answer matches what `mm-isp`
answers directly; a live run also confirmed via `tcpdump -i dslite0` on `mm-aftr` that zero DNS
traffic crossed the softwire. See `test/netns/README.md`.
