# internal/pdlease

minuteman's DHCPv6-PD lease, kept for as long as minuteman runs, as a
[molecule](https://github.com/shun159/molecule) supervision tree: a process climbing the lease's
renewal ladder, and one making each new lease the LAN's. The exchanges and the ladder's times are
`pkg/prefixdelegation`'s, run through the WAN's DHCPv6 client (`internal/dhcpv6client`); what a
lease means for the LAN — addresses, RAs — is `internal/lanprefix`'s, which the caller's `Apply`
runs.

```
dhcpv6-pd (one_for_one)
├── dhcpv6-pd apply   genserver: applies each new lease, by casts
└── dhcpv6-pd lease   genstatem: the renewal ladder
```

## Start

`cmd/minuteman` acquires the lease itself (before AFTR discovery: its DNS servers may be the only
ones there are), applies it, then starts the tree as its `DHCPv6-PD` application with the lease
and `Apply`. The tree applies every lease **after** that one.

## The lease process

A genstatem, pure: each wait is a state timeout, at an absolute time, so the behaviour never reads
the clock; each exchange — which blocks, retransmitting until answered or its deadline passes — is a
`molecule.Async`, whose outcome moves it along:

```
Bound ──(RenewAt, T1)──► Renewing ──fail──► Rebinding ──fail──► Soliciting
  ▲                         │                   │                   │
  └──────── ok: the new lease, cast to the apply process ───────────┘
```

| Phase | Runs | Until |
| --- | --- | --- |
| `Bound` | nothing | `RenewAt` (T1) |
| `Renewing` | `Renew` with the lease's server | `RebindAt` (T2) |
| `Rebinding` | `Rebind` with any server | `ExpiresAt` (the shortest valid lifetime) |
| `Soliciting` | `Acquire`, retrying | it succeeds |

It traps exits: on shutdown, `Terminate` releases the lease (RFC 3315 §18.1.6), bounded to 5s — a
client stops using a binding whether or not the server answers — unless it already expired
(`Soliciting`). The tree stops before the DHCPv6 client, started before it, so the Release has a
client to go through.

A crash releases nothing: the restarted process carries on with the binding, starting from the
lease it was configured with. Before that lease's T1, it still is the lease — nothing has renewed
it; past it, the state timeout fires at once and the ladder runs from there, the server's answer
— the binding as it stands — applied.

## The apply process

A genserver, impure: each cast runs `Apply` — netlink and RA casts — as it is handled. It is apart
from the lease process so that one stays pure, its timers not held up by netlink. `cmd/minuteman`'s
`Apply` keeps what the LAN interfaces were last assigned in its closure, so a restart of either
process loses nothing of it.

## Testing

`go test` drives the lease process's callbacks directly, its exchanges replaced and their Asyncs
run by the test: renewed at T1 and the new lease applied, renewed again at its own T1; the ladder
down to soliciting afresh; a rebound lease bound; a failure soliciting a crash; released on
shutdown, not on a crash, not once expired. End to end, the netns rig's `MM_PD_ZERO_TIMERS=1` has Kea
delegate with `T1 = T2 = 0` and short lifetimes, and checks minuteman renews exactly on the T1 it
derives (see `test/netns/README.md`).
