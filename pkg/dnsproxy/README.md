# pkg/dnsproxy

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

That also means it has no wire format of its own to unit test, which is why it has no `_test.go`
files (the same posture as `pkg/ndproxy`/`pkg/routeradvert`'s raw-socket I/O); its correctness is
exercised by the netns rig.

## `Listen` then `Serve`

Opening is split from serving, the same way `pkg/dhcpv4` splits `New` from `Serve`:

`Listen(Config)` opens a UDP and a TCP socket per `ListenAddrs` on port 53 **synchronously**, and
returns the failure — no upstreams configured, port 53 already in use — to the caller. On any
failure every already-opened socket is closed.

Failing fast matters more here than it looks: `cmd/minuteman` advertises one of these addresses to
LAN clients as their DNS server (RFC 8106 RDNSS, via `routeradvert.Config.RDNSSAddr`) **only
once `Listen` has returned successfully**. A silent bind failure would otherwise leave every
client pointed at a DNS server nothing answers on — worse than advertising none.

A listen address that is IPv6 link-local carries a zone (`netip.Addr.Zone()`, set by
`routeradvert.LinkLocalAddr`), threaded into the `net.UDPAddr`/`net.TCPAddr` so the kernel binds
it to the right interface — `fe80::/10` isn't unique without it.

`Serve(ctx)` runs the forwarding loops and, on `ctx.Done()`, closes every socket to unblock the
read/accept loops — the same close-to-unblock shutdown pattern `pkg/ndproxy`'s `conn`/`packetConn`
use.

## UDP (`udp.go`)

One goroutine **per received datagram**, so one slow or unresponsive upstream never blocks the
next query arriving on the same socket. Each query tries `Config.Upstreams` in order over a
**fresh, one-shot `net.DialUDP` socket**, bounded by `udpQueryTimeout` (5s).

The socket is deliberately not pooled: DNS-over-UDP is a single datagram round trip anyway, and a
dedicated socket means a response can never be confused with a different concurrent query's.

Buffers are `maxUDPMessageBytes` = 65535 rather than DNS's traditional 512, since this package
never parses a message and there is no reason to risk silently truncating a large EDNS0 (RFC
6891) response.

If **every** upstream fails, the query is simply dropped — the client's own resolver retries per
its usual behavior, exactly as if this proxy weren't in the path.

## TCP (`tcp.go`)

One goroutine per accepted connection, relaying to the first upstream that accepts a connection
(`tcpDialTimeout` = 5s each).

`relayTCP` is a full **bidirectional byte-level `io.Copy` relay**, not a framer of individual
length-prefixed DNS-over-TCP messages. RFC 7766 §6.2.1 allows pipelining multiple queries on one
connection, which a byte relay handles for free without this package ever needing to find a
message boundary. Each direction half-closes (`CloseWrite`) when its copy finishes, and the relay
returns once both are done.

## Testing

No `go test` — see "Opaque by design" above. The netns rig's `MM_DNS_PROXY=1` toggle has `mm-host`
`dig` a record through minuteman's LAN gateway IP over **both UDP and TCP** and checks the answer
matches what `mm-isp` answers directly; a live run also confirmed via `tcpdump -i dslite0` on
`mm-aftr` that zero DNS traffic crossed the softwire. See `test/netns/README.md`.
