# internal/ndppd

minuteman's RFC 4389 Neighbor Discovery proxy, for the `-ndproxy` WAN model, as a
[molecule](https://github.com/shun159/molecule) supervision tree: a process owning the proxy's
sockets and its state, and one owning the host routes a confirmed LAN host gets. The protocol --
verifying a host before answering for it, the probes' timing, when a confirmation expires -- is
`pkg/ndproxy`'s; the routes are `internal/wanextend`'s `HostRoutes`; this package is the processes
around them.

```
ndppd (rest_for_one)
├── ndppd routes   genserver: the host routes, installed and removed by casts
└── ndppd proxy    genserver: the WAN and LAN sockets, and the proxy's state
```

rest_for_one because the proxy tells the routes process what to do: a restarted routes process
takes the proxy with it, which starts afresh, re-confirming hosts as the WAN asks for them.

## Start

`cmd/minuteman` starts the tree, as its `NDProxy` application, when `-ndproxy` is given. The routes
process opens its netlink socket (`Config.OpenRoutes`). The proxy's start opens its sockets with
molecule's `net/socket`, so a failure fails the tree's start:

| Socket | Reads | Sends |
| --- | --- | --- |
| WAN, `AF_PACKET` `SOCK_DGRAM` | Neighbor Solicitations (`NSFilter`, `ALLMULTI`) | -- |
| WAN, raw ICMPv6, filtered to nothing | -- | the proxy's Advertisements |
| each LAN, raw ICMPv6 | Neighbor Advertisements | the probes |

The WAN can't be read with a raw ICMPv6 socket: see `pkg/ndproxy`'s README. Every raw socket is
bound to its interface, both hop limits 255 (RFC 4861 §6.1.2).

## The proxy

A genserver, pure: its state is `pkg/ndproxy`'s `State`, a `Clone` of which each event that changes
it is applied to; its sends and socket re-arms are effects; a `sweep` timer every `SweepInterval`
retransmits the probes due and lets hosts gone quiet expire. The clock the `State` is kept by is
the injected `now`, which a behaviour has no other way to read. Every socket is `active once`,
re-armed after each datagram.

| Message | Then |
| --- | --- |
| a Solicitation from the WAN | an Advertisement for a host confirmed recently; a probe on every LAN for one unknown |
| an Advertisement from a LAN answering a probe | the WAN answered; a cast to the routes process to install the host's `/128` out that LAN |
| `sweep` | probes retransmitted; for a host expired, a cast to remove its route |

A send failing is logged: NDP retransmits, and the next Solicitation or sweep gets another chance.
A socket failing to read, or closing, stops the proxy, and its supervisor restarts it.

## The routes process

A genserver, impure: each cast is a netlink round trip, done as it is handled. A failure to install
is logged, not fatal -- without its route, a host's traffic keeps arriving proxied and unrouted, no
worse than before it was confirmed. It traps exits, so its `Terminate` closes the netlink socket on
shutdown.

## Testing

`go test` drives the proxy's callbacks directly, its sends and socket arming swapped for effects the
test reads: an unknown host probed on every LAN, its Advertisement answered on the WAN and its route
installed, the next Solicitation answered at once; a DAD-style Solicitation answered to all nodes; a
stray Advertisement ignored; a sweep retransmitting, then expiring a host's route. End to end, the
netns rig's `MM_WAN_MODEL=ndproxy` has `mm-isp` ping `mm-host`'s SLAAC address, which only succeeds
if the whole chain worked (see `test/netns/README.md`).
