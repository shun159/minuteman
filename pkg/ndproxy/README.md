# pkg/ndproxy

The subset of RFC 4389 (Neighbor Discovery Proxy) a CPE needs when the ISP hands out a single
on-link `/64` on the WAN with no prefix delegation: answering Neighbor Solicitations on the WAN
link on behalf of hosts that actually live behind the CPE on a LAN link, so upstream traffic for
them resolves to the CPE's own MAC and gets forwarded.

The CPE-policy half — learning which prefix to extend, re-advertising it, installing host
routes — is `internal/wanextend`. This package is the protocol, with no sockets: the process
owning the sockets and running it is `internal/ndppd`.

## Verify, don't snoop

The obvious implementation passively snoops LAN NS/NA traffic to learn which addresses exist.
This one doesn't, and the difference is the package's central design decision:

```
WAN: NS for target ──► unknown? ──► LAN: NS probe out every LAN interface
                                          │
                                          └── real NA back ──► WAN: NA on target's behalf
                                                               + Reply{target, iface}: route it
```

Snooping would need `ALLMULTI` on every LAN interface and would have the proxy answering from
state that may be arbitrarily stale. Actively probing means the proxy replies **only for hosts
that exist right now**, and it is the same shape ndppd's "auto" mode uses.

## Files

| File | Role | Pure? |
| --- | --- | --- |
| `message.go` | NS/NA wire codec (package doc lives here) | yes |
| `wire.go` | what the sockets send and read: `Solicitation`, `Advertisement`, `ParseAdvertisement`, `ICMPv6Filter` | yes |
| `packet.go` | what the WAN `AF_PACKET` socket reads: `NSFilter`, `ParseSolicitationPacket` | yes |
| `state.go` | `State` — all decision logic | yes |

`message.go` is marshal-only for the proxy's own probes and replies, parse-only for extracting a
`Target Address`. Options are never decoded, because the proxy never needs a peer's link-layer
address.

## Two different sockets, and why

The sockets are `internal/ndppd`'s; what they need from the protocol is here.

**LAN side** — an ordinary raw `IPPROTO_ICMPV6` socket, filtered to one message type via
`ICMP6_FILTER` (`ICMPv6Filter`; `ICMP6Filter` vendored the same way `pkg/routeradvert` vendors
it), hop limits at 255 per §6.1.2. The proxy's Advertisements go out a raw socket on the WAN too,
filtered to nothing.

**WAN side (`packet.go`)** — cannot receive on a raw ICMPv6 socket at all. A Neighbor Solicitation is
sent to the *target's* Solicited-Node multicast group — a **different group per target address** —
and the kernel drops multicast for groups never joined before a raw socket would ever see it.
So the WAN receiver is a cooked `AF_PACKET` socket (matching ndppd's own approach) with `ALLMULTI`
plus a classic-BPF filter (`NSFilter`), so only Neighbor Solicitations reach userspace.

`ALLMULTI` is held via the packet socket's own `PACKET_MR_ALLMULTI` membership rather than an
`IFF_ALLMULTI` ioctl, so the kernel drops it automatically when the socket closes — even on a
crash.

## `State` (`state.go`)

Pure decision logic: no I/O, and **every method takes an explicit `now time.Time`** instead of
reading the clock, so it is unit-tested with no sockets and no timers. Same rationale as
`pkg/dhcpv4`'s `Pool` and `internal/wanextend`'s `nextWatchState`.

| Method | Question it answers |
| --- | --- |
| `OnWANSolicit(now, target, solicitor)` | reply now, start a probe, or neither? |
| `OnLANAdvert(now, iface, target)` | does this NA match a probe in flight? |
| `Sweep(now)` | what to retransmit, give up on, or expire (every `SweepInterval`) |

It changes in place; `Clone` gives a copy that changes independently, which a process whose
state must not change under it (a molecule behaviour) applies an event to.

- A target already confirmed and **fresh** (within `activeTTL`) is answered immediately, no
  probing.
- A probe already in flight for that target means *neither* return fires: a duplicate probe would
  be wasteful, and the pending one's eventual resolution covers this solicitor too. Only the most
  recent solicitor is kept — RFC 4861 doesn't require answering every asker individually, just
  resolving the target once.
- Probes retransmit on §10's `RetransTimer` (1s) up to `MAX_MULTICAST_SOLICIT` (3), then give up
  **without ever having replied** — correctly not claiming a target that doesn't exist.

`activeTTL` (5 minutes) is a **CPE-local policy choice, not RFC-mandated**: long enough that
normal traffic doesn't cause constant re-probing (an upstream neighbor cache entry is typically
reused for tens of seconds to minutes), short enough that a LAN host going away is eventually
noticed rather than proxied forever.

## Deliberate non-goals vs. full RFC 4389

Documented on the package itself:

- **No cross-link DAD proxying** — the odds of an address collision between WAN and LAN hosts
  within one `/64` of SLAAC addresses are negligible.
- **No RA/Redirect proxying** — the caller re-advertises the WAN prefix on the LAN itself with
  the on-link flag cleared (`routeradvert.Config.OnLink = false`), which routes LAN hosts through
  the CPE for everything and means LAN-side NS proxying is never needed.
- **No proxy-loop detection** — a second ND proxy on the LAN is out of scope.

## Testing

```sh
go test ./pkg/ndproxy/           # message_test.go, state_test.go
```

The state machine and the codec are unit-tested, the process around them in `internal/ndppd`;
the sockets are exercised by the netns rig with
`MM_WAN_MODEL=ndproxy`, which has `mm-isp` — L2-adjacent to the CPE's WAN link and itself the
origin of the on-link RA there — ping `mm-host`'s SLAAC address directly. That only succeeds if
the NS was intercepted on the WAN, the target verified by a LAN-side probe, answered on its
behalf, and the host route installed. See `test/netns/README.md`.
