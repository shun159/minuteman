# internal/dhcpv6client

The WAN's DHCPv6 client: a [molecule](https://github.com/shun159/molecule) process owning the
interface's client socket, `[link-local%iface]:546`, for as long as it lives, and running the
exchanges `pkg/dhcpv6` describes over it, one at a time. A `Client` is the `dhcpv6.Exchanger` that
`pkg/aftrdiscovery` (Information-Request) and `pkg/prefixdelegation` (Solicit, Request, Renew,
Rebind, Release) are given.

## One process, one socket

`pkg/dhcpv6` used to bind the socket afresh for each exchange, and serialize exchanges on an
interface with a lock, since two binds of the same `:546` collide (`EADDRINUSE`) and minuteman
really does run exchanges concurrently -- DHCPv6-PD maintenance alongside AFTR re-discovery. Here
the socket is bound once, when the process starts, and the process runs one exchange at a time:
one arriving while another runs is a postponed event, handled when the client is idle again.

The socket is **bound, never connected**: a connected socket only accepts datagrams from the
address it is connected to, but the server's Reply comes unicast from the server's own address,
not from the multicast destination the request went to. Binding to the zone-qualified link-local
address also fixes the outgoing interface for the multicast request (Linux sets the socket's bound
device, which route lookups consult before `IPV6_MULTICAST_IF`). Binding it waits out a
DAD-tentative address (`bindRetries`), as after the link bounces.

The child's start binds the socket, so an interface with no usable link-local address fails the
start rather than the first exchange.

## The machine (`machine.go`)

A genstatem, pure: it returns the datagrams to send as effects, and draws its randomness --
transaction IDs, RFC 3315 §14 jitter -- from a `rand.PCG` kept in its data, seeded at start.

| Phase | Waiting for |
| --- | --- |
| `Idle` | an exchange request |
| `Delaying` | the random delay before the first transmission (Information-Request, Solicit) |
| `Waiting` | an answer, until the retransmission timeout; then it retransmits, or gives up with `dhcpv6.ErrExhausted` past the exchange's MRC |

A datagram is taken as the answer when `Exchange.Answers` says so -- the expected type and
transaction, a server identifier, our client identifier if echoed; anything else is dropped and
the exchange goes on. The elapsed time each retransmission carries is the sum of the timeouts
waited so far. The socket is armed `Once` per transmission and per datagram dropped, so it reads
only while an exchange waits.

## Giving up

`Client.Exchange` is a `molecule.Call` with the caller's `ctx`. When that is done first, the Call
tells the machine with a `molecule.CallAbandoned`: genstatem drops the exchange if it is still
waiting its turn, postponed; if it is the one running, the machine gets the `CallAbandoned` and
drops it, which frees the client for the next. This is how the callers' deadlines work as they
did: a Renew bounded by T2, an Information-Request by `aftrdiscovery`'s `replyTimeout`.

## Lifetime

`cmd/minuteman` starts the client, as the first of its applications, before DHCPv6-PD and AFTR
discovery need it. The applications stop in reverse order, after everything else of minuteman's,
so the client stops last, after everything that might still exchange on the way out: the PD
maintenance sends its Release through it on shutdown. A socket that fails stops the process, and its supervisor binds a new one.

## Testing

`go test` runs the process against a fake DHCPv6 server on the IPv6 loopback: an exchange answered,
retransmission with the same transaction and a growing elapsed time, `ErrExhausted` past the MRC,
non-answers ignored, exchanges run one at a time, and giving up on an exchange running or waiting
its turn. End to end, the netns rig's Kea exercises it through DHCPv6-PD and AFTR discovery.
