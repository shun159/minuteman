# internal/lanprefix

The **policy** layer for a DHCPv6-PD delegated prefix: what a CPE should *do* with the `/56`
(or whatever) its ISP delegates, as opposed to the protocol client that obtained it.

The split is deliberate and mirrors `internal/wanextend`'s split from `pkg/ndproxy`:

- `pkg/prefixdelegation` speaks RFC 3633 — Solicit/Request/Renew/Rebind, IA_PD option
  encoding, the T1/T2 renewal ladder. It knows nothing about LAN interfaces.
- `internal/lanprefix` decides that LAN interface *i* gets the *i*'th `/64` out of the
  delegation, that the CPE takes `::1` in it, and that the `/64` is advertised to LAN clients
  with the On-Link flag set. None of that is in any RFC; it's this project's policy.

`cmd/minuteman`'s `runPrefixDelegation` is the only caller, and it uses this package twice:
once synchronously at startup (so the datapath isn't reported "up" before the LAN addresses
exist) and then as `prefixdelegation.Maintain`'s `onLeaseChange` callback, so every renewal
runs the same `Reconcile` + `RAManager.Sync` pair.

## Files

### `carve.go` — pure prefix arithmetic

`SubnetFor(delegated, index)` writes `index` into the bits between the delegated prefix
length and bit 64. A `/56` delegation has 8 such bits, so `-lan` interfaces 0..255 each get a
distinct `/64`; an index past that capacity, a delegation already narrower than a `/64`, or a
non-IPv6 prefix is an error rather than a silent wrap.

`AssignedAddress(subnet)` is the CPE's own address in that `/64`: the network address with
the last byte set to 1, i.e. the conventional `::1` gateway.

`/64` is fixed rather than configurable because SLAAC cannot work with anything narrower, and
`RAManager` advertises these prefixes for exactly that purpose.

Both functions are pure `netip` bit manipulation with no I/O, which is why `carve_test.go`
covers them with an ordinary `go test`.

### `reconcile.go` — netlink address assignment

`Reconcile(delegated, validLifetime, preferredLifetime, lanIfaces, prev)` opens one
`pkg/netlink.Socket` for the whole call and, per LAN interface, carves its subnet, derives its
address, and assigns it.

`prev` is the previous call's return value, and it is what makes renewal cheap and correct:

- subnet unchanged since last time → both netlink calls are skipped entirely, so a Renew that
  re-delegates the same prefix causes no route churn on the LAN;
- subnet changed → the stale address is removed (`RTM_DELADDR`) *before* the new one is added
  (`RTM_NEWADDR`), so a renumbering doesn't leave the interface holding both.

Per-interface failures are collected with `errors.Join` rather than aborting: one missing LAN
interface must not stop the others from being configured. The returned slice always has one
`Assignment` per `lanIfaces` — including entries that errored, so the next `Reconcile` has a
baseline to retry from.

`Assignment` also carries the delegated prefix's `ValidLifetime`/`PreferredLifetime` straight
through (taken from the IA_PD Prefix option, not derived here) so `ra.go` can advertise
lifetimes that track the actual upstream delegation.

### `ra.go` — what each LAN interface advertises

`RAManager` decides each LAN interface's Router Advertisement configuration -- its
currently-assigned `/64` with **`OnLink: true`**, a PD delegation really being distinct and
on-link per interface, unlike `internal/wanextend`'s shared-WAN-prefix model, which must clear
that flag -- and hands it to an `Advertiser`: `internal/radvd`'s advertiser of that interface.

The advertiser takes a new configuration **in place**, never restarting. This is load-bearing,
not an optimization. A DHCPv6-PD Renew resets the lifetimes on every lease change, so `Sync` is
reached once per T1 interval even when nothing about the subnet moved. Restarting the advertiser
would deliver the refreshed lifetimes too -- but its shutdown sends RFC 4861 §6.2.5's
`RouterLifetime=0` advertisement (and, since the RDNSS option's lifetime tracks it, withdraws the
DNS server as well). Every LAN client would therefore see its default route and resolver
withdrawn once per renewal and reinstated a moment later. That flap was a real bug; it is §1 of
`docs/rfc-compliance-backlog.md`, now resolved.

An `Assignment` with an invalid `Subnet` (its `Reconcile` failed) is skipped, leaving the
interface advertising what it did rather than tearing it down over a transient error. An
advertiser whose socket fails is restarted by its supervisor, idle until the next `Sync` -- the
next PD renewal -- as a failed worker used to be replaced only at the next `Sync`.

## Testing

```sh
go test ./internal/lanprefix/          # carve.go's pure functions
```

`Reconcile` and `RAManager` touch netlink and raw sockets, so they are exercised end-to-end by
the netns rig instead (`MM_WAN_MODEL=dhcpv6-pd`, the default). `MM_PD_ZERO_TIMERS=1` waits out
a real renewal, so `Reconcile`/`Sync` are actually driven a second time on a live lease — it
asserts the renewal happened, that it wasn't a storm, and that the carved LAN address survived
it unchanged. See `test/netns/README.md`.
