# internal/radvd

The Router Advertisements of minuteman's LAN interfaces, as a
[molecule](https://github.com/shun159/molecule) supervision tree: one process per `-lan` interface,
owning its raw ICMPv6 socket, advertising the `routeradvert.Config` last given to it. What to
advertise is `internal/lanprefix`'s (DHCPv6-PD) or `internal/wanextend`'s (NDProxy) to decide; the
RA and its timing are `pkg/routeradvert`'s.

```
radvd (one_for_one)
├── radvd <iface>   genserver: the interface's raw ICMPv6 socket
└── ...
```

## Start

`cmd/minuteman` starts the tree, as one of its applications, when either model runs. A child's
start opens its socket with molecule's `net/socket`: raw ICMPv6, bound to the interface, in the
All-Routers group, both hop limits 255 (RFC 4861 §6.1.2), filtered to Router Solicitations
(`routeradvert.SolicitationFilter`). The advertiser is then **idle**: it advertises nothing, and
answers no Solicitation, until it is given a `Config` (`Advertiser.Advertise`, a cast).

## The advertiser

A genserver, pure: every wait of RFC 4861 §6.2/§10 is a timer, the RAs are effects, and its
randomness comes from a `rand.PCG` in its state.

| Timer | Fires | Then |
| --- | --- | --- |
| `unsolicited` | at once on a first or changed `Config`; then after `NextUnsolicitedInterval` | sends an RA, schedules the next |
| `quiet` | `MinDelayBetweenRAs` after any RA | lets the next one go; sends a `Config` that changed meanwhile |
| `reply` | up to 500ms after a Solicitation (`ReplyDelay`) | answers it, unless an RA went meanwhile |

A Solicitation within `MinDelayBetweenRAs` of the last RA is answered by that RA. A changed
`Config` is advertised at once, or as soon as the floor allows -- **in place**: a restart would
announce `RouterLifetime=0` first, withdrawing the router and its RDNSS server from every LAN client
for the changeover (see `internal/lanprefix`'s README). The same `Config` again changes nothing.

A send failing with `EADDRNOTAVAIL` -- the link-local still DAD-tentative, right after an XDP attach
bounces the link -- is retried after `TentativeRetryInterval`; another failure stops the advertiser,
and its supervisor restarts it, idle until it is next given a `Config`.

On shutdown -- the advertiser traps exits -- `Terminate` sends one final RA with `RouterLifetime=0`
(§6.2.5), telling clients to stop using this router, and, its lifetime tracking the router's, this
DNS server.

## Testing

`go test` drives the advertiser's callbacks directly, its sends and socket arming swapped for
effects the test reads: idle until configured; an RA at once, then the initial burst's cadence,
`MinDelayBetweenRAs` honoured for Solicitations and changes; the steady cadence varying; the
tentative retry; the final RA's lifetime 0. End to end, the netns rig has `mm-host` SLAAC an
address out of what is advertised, and pick up its RDNSS server.
