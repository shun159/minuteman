# pkg/netlink

A minimal, hand-rolled `AF_NETLINK`/`NETLINK_ROUTE` client covering exactly what minuteman's
policy layers need — nothing more. No netlink library dependency: it builds and parses the wire
messages itself over `golang.org/x/sys/unix`.

That is the same no-sidecar, no-external-dependency stance the rest of the project takes
(`pkg/datapath/sysctl.go` writes `/proc/sys` files rather than exec'ing `sysctl`;
`pkg/routeradvert` hand-rolls its ICMPv6 socket rather than pulling in `x/net/icmp`). This
package was originally private to `internal/lanprefix` and was split out once
`internal/wanextend` needed the same mechanism.

**It is the only package that builds or parses netlink wire messages.**

## Callers

| Caller | Uses |
| --- | --- |
| `internal/lanprefix` | `AddAddr` / `DelAddr` (LAN address assignment) |
| `internal/wanextend` | `Addrs` (WAN prefix discovery), `AddRoute` / `DelRoute` (`/128` host routes) |
| `internal/slowpath` | `AddIP6Tnl`, `SetIP6TnlEndpoints`, `SetLinkMTU`, `SetLinkUp`, `DelLink`, `AddRoute` |
| `internal/fragpath` | `AddVeth`, `SetLinkUp`, `DelLink` |
| `cmd/minuteman` | `SourceForDest` (dynamic B4 selection) |

## `Socket`

One socket, **not safe for concurrent use** — a single-writer request/reply channel (one `Send`,
one `Recvfrom`, matched by an incrementing sequence number). Unsynchronized callers would consume
each other's ACKs and report failures for requests that in fact succeeded, which is exactly why
`internal/slowpath.Tunnel` takes a mutex around its two independent drivers.

### Addresses

`AddAddr` / `DelAddr` assign and remove an address. `AddAddr` sends `NLM_F_REPLACE`, which makes
it **idempotent** — re-asserting an already-assigned address succeeds.

`Addrs(ifindex)` is an `RTM_GETADDR` dump, looping `Recvfrom` until `NLMSG_DONE` (a dump response
packs several messages into one buffer, which `walkMessages` splits). It filters to global scope
(`RT_SCOPE_UNIVERSE`): WAN-prefix discovery has no use for the interface's link-local address.

### Routes

`AddRoute` / `DelRoute` handle a **directly-attached** route — `RTA_OIF` only, no `RTA_GATEWAY`,
scope `RT_SCOPE_LINK` — i.e. the equivalent of `ip route add <dst> dev <iface>`. The family
follows the prefix, so one call serves both `internal/wanextend`'s IPv6 `/128` host routes and
`internal/slowpath`'s IPv4 default route; a `/0` prefix omits `RTA_DST`. `AddRoute` is
`NLM_F_REPLACE`-idempotent too.

### `SourceForDest` — the dynamic-B4 query

An `RTM_GETROUTE` query (the equivalent of `ip route get <dst> oif <ifindex>`) returning the
kernel's chosen source from `RTA_PREFSRC`. It exists so minuteman can pick the B4's own softwire
source toward the AFTR **without reimplementing RFC 6724 source-address selection** —
deprecated-avoidance, scope match, longest match — and so it picks the exact source the kernel's
own ip6tnl would.

Its three-valued return is load-bearing. `ok = false` means "no usable source **yet**": the
kernel reported the destination unreachable out this interface (`ENETUNREACH`/`EHOSTUNREACH`/
`ENETDOWN`), or answered with a route carrying no `RTA_PREFSRC`. That is the expected state at
startup, before the WAN's RA-learned default route is back, and the caller retries. Any *other*
errno — `EINVAL` from a malformed request, say — is returned as a real error instead, so a bug
surfaces rather than looping forever.

### Links

`AddIP6Tnl(name, local, remote, mtu)` creates the DS-Lite companion device in `ipip6` mode with
`encaplimit none`; `SetIP6TnlEndpoints` repoints an existing one **in place** via changelink, so
a WAN renumbering or AFTR migration doesn't tear down the IPv4 default route pointing at it.
`AddVeth(name, peerName, mtu)` creates the fragmentation companion pairs. Both use `NLM_F_EXCL`
and so fail if the device exists — callers delete a stale one first, which is the lifecycle
`internal/slowpath` and `internal/fragpath` both implement.

`SetLinkUp`, `SetLinkMTU` and `DelLink` round it out. `SetLinkMTU` exists specifically because the
companion ip6tnl's MTU has to follow a learned softwire path MTU, or the fallback keeps
fragmenting to a size the path drops.

An `EOPNOTSUPP` from `AddIP6Tnl` means the `ip6_tunnel` kernel module is unavailable; callers
surface that rather than degrading silently.

## Message building (`message.go`)

`walkMessages` splits a `Recvfrom` buffer into individual messages; `parseIfAddrMsg` decodes an
`RTM_NEWADDR` dump entry's `IFA_ADDRESS`/`IFA_LOCAL` attributes.

`encodeNestedAttr` is the container-attribute primitive the `IFLA_LINKINFO` / `IFLA_INFO_DATA`
nesting needs — a plain `encodeRtAttr` over concatenated already-encoded children, which works
because every attribute is 4-byte aligned. On top of it sit `buildAddIP6TnlMessage`,
`buildChangeIP6TnlMessage`, `buildAddVethMessage` (the peer described by its own `ifinfomsg`
nested in `VETH_INFO_PEER`), `buildSetLinkUpMessage` and `buildDelLinkMessage`.

The `IFLA_IPTUN_*` attribute codes and the `IP6_TNL_F_IGN_ENCAP_LIMIT` flag are `#define`d
locally, since `x/sys/unix` doesn't export them — the same vendoring rationale as
`pkg/routeradvert`'s `ICMP6_FILTER` and `bpf/uapi/linux/*.h`.

## Testing

```sh
go test ./pkg/netlink/           # message_test.go: wire encoding/decoding, no sockets
```

`srcfordest_live_test.go` is a **live** test against the netns rig: it runs inside `mm-cpe` and
asserts the kernel's chosen source toward the AFTR is an address the WAN interface actually has.
It skips itself unless `MM_RIG_WAN` is set to the WAN interface name and it is running as root
inside that namespace — with the rig up (`test/netns/setup.sh`), that means entering `mm-cpe` and
setting `MM_RIG_WAN=v-cpe-isp`. See `test/netns/README.md`.
