# internal/wanextend

The **policy** layer for the other WAN provisioning model: an ISP that hands out a single
on-link `/64` on the WAN interface and no DHCPv6-PD delegation at all. There is no second
prefix to give the LAN, so the WAN's own `/64` is *extended* onto it, and RFC 4389 Neighbor
Discovery Proxy is what makes the upstream router believe the LAN hosts are on its link.

This package is to `pkg/ndproxy` what `internal/lanprefix` is to `pkg/prefixdelegation`: the
protocol package answers Neighbor Solicitations and knows nothing about CPE topology; this one
decides where the prefix comes from, how it is advertised, and what a confirmed-active target
implies for the routing table. `-ndproxy` and `-dhcpv6-pd` are mutually exclusive — they are
alternative models of the same thing, and `cmd/minuteman` rejects both at once before anything
starts.

`Serve` is the single entry point `cmd/minuteman`'s `runNDProxy` calls.

## Flow

```
DiscoverPrefix ──► raManager.sync ──► one routeradvert.Serve per LAN iface (OnLink: false)
      │
      ├──► WatchChanges ──(renumbering)──► raManager.sync with the new prefix
      │
      └──► ndproxy.Serve on the WAN iface
                 ├─ OnActive   ──► HostRoutes.Install  (/128 out the confirming LAN iface)
                 └─ OnInactive ──► HostRoutes.Remove
```

## Files

### `discover.go` — learning and re-learning the WAN prefix

`DiscoverPrefix(ctx, wanIfindex)` blocks, polling `pkg/netlink.Socket.Addrs` every 2s, until
the WAN interface has a global-scope IPv6 address to report, and returns it masked to its
network. It has to block: RA/SLAAC lands asynchronously some time after the WAN link comes up
(after `AttachWAN` and `cmd/minuteman`'s `SolicitRouters`), and until it does there is nothing
to extend onto the LAN — NDProxy's whole premise. The poll interval isn't an RFC cadence, just
"notice quickly without busy-polling".

`WatchChanges(ctx, wanIfindex, current, onChange)` re-polls every **5 minutes** and calls
`onChange` only for a genuinely different, valid reading. The much slower cadence is
deliberate: there is no DHCPv6-style T1/T2 ladder to drive here — the kernel manages its own
address lifetimes off whatever RAs arrive, so this package can only notice a renumbering after
the fact — and RFC 4861 mandates no cadence for doing so. Five minutes is a CPE-local policy
choice.

A tick that errors, or that momentarily finds no global address (exactly what a mid-renumbering
WAN looks like), is **not** reported: the last-known prefix keeps being advertised until a real
replacement is confirmed. Tearing down a working advertisement over a one-tick blip is the
worse failure, the same conservative stance `pkg/routeradvert` takes on `EADDRNOTAVAIL`.

That decision is factored out as the pure `nextWatchState(current, next, err)` precisely so it
is unit-testable without a clock or a netlink socket — the same rationale behind
`pkg/ndproxy`'s `proxyState` taking an explicit `now`.

### `ra.go` — re-advertising the shared prefix, with On-Link cleared

`raManager` drives one `pkg/routeradvert.Serve` goroutine per LAN interface, all advertising
**the same** prefix — unlike `internal/lanprefix.RAManager`, which advertises a distinct
subnet per interface, so `sync()` takes a single `netip.Prefix` rather than a per-interface
list.

`OnLink: false` is the crux of the model. The `/64` is shared with the WAN, so if LAN clients
believed it were on-link they would try to reach WAN neighbours directly. Clearing the flag
makes them route *everything*, not just off-prefix traffic, through the CPE — which is what
lets WAN-side proxying alone deliver reachability, with no LAN-side proxying needed.

Like `lanprefix.RAManager.Sync`, `sync` updates a running worker in place via a
`routeradvert.Updater` rather than restarting it, for the same reason: cancellation is
`Serve`'s shutdown path and announces `RouterLifetime=0` first, so a restart on a WAN prefix
change would cost every LAN client its default route and RDNSS server for the length of the
changeover. Nothing about renumbering is lost by not restarting — that final RA never
deprecated the outgoing prefix anyway, since its Prefix Information Option carries the old
lifetimes intact. Advertising the superseded prefix with `PreferredLifetime=0` to deprecate it
promptly is RFC 9096 territory and an open item in `docs/rfc-compliance-backlog.md`.

The advertised lifetimes are RFC 4861 §6.2.1's recommended defaults (30 days valid / 7 days
preferred), **not** the WAN RA's actual remaining lifetimes: `DiscoverPrefix`/`WatchChanges`
read the prefix back from the kernel's address list, which doesn't expose `IFA_CACHEINFO`. A
known simplification, not a protocol requirement.

### `hostroutes.go` — per-target `/128` routes

`HostRoutes` matches `pkg/ndproxy.Config`'s `OnActive`/`OnInactive` callback shapes and wraps
one long-lived `pkg/netlink.Socket` for the lifetime of a `ndproxy.Serve` run. No locking:
`Serve` only ever fires those callbacks from its own single `select` loop.

The routes exist because the shared-`/64` model gives the kernel no way to know which LAN
interface a confirmed-active target lives behind — wrong whenever there is more than one LAN
interface, and unpredictable even with one. `Install` adds the `/128` out the interface that
confirmed the target.

`Remove` logs rather than returns errors (`OnInactive` has no error return, unlike
`OnActive`): a route that outlives its target is stale but harmless — nothing routes to it once
`Serve` stops confirming the target — and a later reactivation's `Install` overwrites it via
`NLM_F_REPLACE` anyway.

### `serve.go` — wiring it together

`Serve(ctx, wanIface, wanIfindex, lanIfaces, rdnssByIface, wg)` blocks on the initial
`DiscoverPrefix` (nothing else can usefully start first, the same rationale
`runPrefixDelegation` applies to its own initial `Acquire`), then starts every background
goroutine and registers each on the caller's `sync.WaitGroup` so `cmd/minuteman`'s shutdown
can wait for the final RAs and `ndproxy`'s socket closes to finish.

A non-nil return means the initial discovery failed or was cancelled. Past that point `Serve`
returns nil and leaves its goroutines running until `ctx` is cancelled.

`rdnssByIface` is forwarded to every LAN RA worker and carries the same meaning as in
`internal/lanprefix`: LAN interface → the link-local address `pkg/dnsproxy` actually bound
there, so an RDNSS option is only ever advertised for a resolver that really answers.

## Testing

```sh
go test ./internal/wanextend/          # nextWatchState
```

Everything else is socket and netlink I/O, exercised end-to-end by the netns rig with
`MM_WAN_MODEL=ndproxy`. That mode has `mm-isp` — itself the origin of the on-link WAN RA —
ping `mm-host`'s SLAAC address directly, which only succeeds if the whole chain worked:
`pkg/ndproxy` intercepted the Neighbor Solicitation on the WAN link, actively verified the
target with a LAN-side probe, answered on its behalf, and `HostRoutes` installed the resulting
route. See `test/netns/README.md`.
