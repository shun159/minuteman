# pkg/ndproxy

The subset of RFC 4389 (Neighbor Discovery Proxy) a CPE needs when the ISP hands out a single
on-link `/64` on the WAN with no prefix delegation: answering Neighbor Solicitations on the WAN
link on behalf of hosts that actually live behind the CPE on a LAN link, so upstream traffic for
them resolves to the CPE's own MAC and gets forwarded.

The CPE-policy half — learning which prefix to extend, re-advertising it, installing host
routes — is `internal/wanextend`. This package is the protocol.

## Verify, don't snoop

The obvious implementation passively snoops LAN NS/NA traffic to learn which addresses exist.
This one doesn't, and the difference is the package's central design decision:

```
WAN: NS for target ──► unknown? ──► LAN: NS probe out every LAN interface
                                          │
                                          └── real NA back ──► WAN: NA on target's behalf
                                                               + OnActive(target, iface)
```

Snooping would need `ALLMULTI` on every LAN interface and would have the proxy answering from
state that may be arbitrarily stale. Actively probing means the proxy replies **only for hosts
that exist right now**, and it is the same shape ndppd's "auto" mode uses.

## Files

| File | Role | Pure? |
| --- | --- | --- |
| `message.go` | NS/NA wire codec (package doc lives here) | yes |
| `state.go` | `proxyState` — all decision logic | yes |
| `conn.go` | LAN-side raw ICMPv6 socket (probes out, NAs in) | no |
| `packet.go` | WAN-side `AF_PACKET` receiver | no |
| `serve.go` | `Serve` — the one `select` loop wiring it together | no |

`message.go` is marshal-only for the proxy's own probes and replies, parse-only for extracting a
`Target Address`. Options are never decoded, because the proxy never needs a peer's link-layer
address.

## Two different sockets, and why

**LAN side (`conn.go`)** — an ordinary raw `IPPROTO_ICMPV6` socket, filtered to one message type
via `ICMP6_FILTER` (vendored the same way `pkg/routeradvert` vendors it), hop limits at 255 per
§6.1.2.

**WAN side (`packet.go`)** — cannot use a raw ICMPv6 socket at all. A Neighbor Solicitation is
sent to the *target's* Solicited-Node multicast group — a **different group per target address** —
and the kernel drops multicast for groups never joined before a raw socket would ever see it.
So the WAN receiver is a cooked `AF_PACKET` socket (matching ndppd's own approach) with `ALLMULTI`
plus a classic-BPF filter (`nsFilter`), so only Neighbor Solicitations reach userspace.

`ALLMULTI` is held via a **dedicated packet socket's** group membership rather than an
`IFF_ALLMULTI` ioctl, so the kernel drops it automatically when the socket closes — even on a
crash. (That socket has protocol 0, so it receives nothing itself.)

## `proxyState` (`state.go`)

Pure decision logic: no I/O, and **every method takes an explicit `now time.Time`** instead of
reading the clock, so it is unit-tested with no sockets and no timers. Same rationale as
`pkg/dhcpv4`'s `Pool` and `internal/wanextend`'s `nextWatchState`.

| Method | Question it answers |
| --- | --- |
| `onWANSolicit(now, target, solicitor)` | reply now, start a probe, or neither? |
| `onLANAdvert(now, iface, target)` | does this NA match a probe in flight? |
| `sweep(now)` | what to retransmit, give up on, or expire |

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

## `Serve` (`serve.go`)

`Serve(ctx, wanIface, lanIfaces, Config)` opens every socket, then runs one `select` loop over
three inputs: the WAN NS channel, a fanned-in LAN NA channel (tagged with its source interface,
since `conn` doesn't know its own name), and the sweep ticker. Blocks until `ctx` is cancelled.

`Config` has two optional hooks:

- **`OnActive(target, iface) error`** — a target was confirmed behind `iface`. The caller's chance
  to install a host route so the kernel forwards its traffic out the right LAN interface.
  `internal/wanextend.HostRoutes` does. A returned error is logged, not fatal: without the route,
  traffic just keeps arriving proxied and unrouted — no worse than before activation.
- **`OnInactive(target, iface)`** — the entry aged out. No error return, since a stale route is
  harmless and a later reactivation overwrites it.

**Every channel send in this package is non-blocking and drops on full** (`select` + `default`).
NDP retransmits, so a dropped message costs a retransmission interval of delay, not a lost
resolution — whereas a blocking send would leak a goroutine past `Serve` returning. Send failures
on the sockets are likewise logged rather than failing `Serve`: the next retransmitted
solicitation gets another chance.

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

The state machine and the codec are unit-tested; the sockets are exercised by the netns rig with
`MM_WAN_MODEL=ndproxy`, which has `mm-isp` — L2-adjacent to the CPE's WAN link and itself the
origin of the on-link RA there — ping `mm-host`'s SLAAC address directly. That only succeeds if
the NS was intercepted on the WAN, the target verified by a LAN-side probe, answered on its
behalf, and the host route installed. See `test/netns/README.md`.
