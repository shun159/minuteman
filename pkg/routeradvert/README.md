# pkg/routeradvert

The subset of RFC 4861 (Neighbor Discovery) a CPE actually needs — no more:

- **LAN side**: send Router Advertisements carrying a Prefix Information Option, so LAN clients
  SLAAC an address (`Serve`).
- **WAN side**: send Router Solicitations upstream, so the CPE's *own* host role gets a default
  route back promptly (`SolicitRouters`).

Not the full NDP message set: no Neighbor Solicitation/Advertisement (that's `pkg/ndproxy`), no
Redirects. The wire codec is **marshal-only** — this package never needs to decode an RA or an
RS body, only to notice that an RS arrived (`isRouterSolicitation`).

Both `internal/lanprefix` and `internal/wanextend` drive one `Serve` goroutine per LAN interface;
what differs between them is `Config.OnLink`.

## Files

| File | Role |
| --- | --- |
| `message.go` | RA fixed header + `RouterSolicitation` framing (package doc lives here) |
| `options.go` | `PrefixInformation` (§4.6.2), `SourceLinkLayerAddress` (§4.6.1), RDNSS (RFC 8106) |
| `transport.go` | the raw ICMPv6 socket (`Conn`), `LinkLocalAddr` |
| `advertise.go` | `Config`, `Updater`, `Serve` — the §6.2/§10 timing |
| `solicit.go` | `SolicitRouters` — §6.3.7's host cadence |

Framing is manual byte-slice work, matching `pkg/dhcpv6`'s style.

## `Config`

| Field | Notes |
| --- | --- |
| `Prefix` | advertised in a PIO with the Autonomous flag **always** set |
| `OnLink` | the PIO's L flag — see below |
| `ValidLifetime` / `PreferredLifetime` | |
| `RDNSSAddr` | when valid, adds an RFC 8106 RDNSS option |

`OnLink` is the one knob that distinguishes the two WAN provisioning models:

- **true** (`internal/lanprefix`, DHCPv6-PD): this `/64` really is distinct and on-link for this
  LAN interface, so clients route through the CPE only for destinations outside it.
- **false** (`internal/wanextend`, NDProxy): the `/64` is shared with the WAN, so clients must
  route **everything** through the CPE — which is what makes WAN-side ND proxying alone deliver
  reachability, per RFC 4389, instead of also needing LAN-side proxying.

`RDNSSAddr` is a concrete address, not an "advertise RDNSS" boolean, and that is deliberate: RFC
7084 §L-11 wants an IPv6-only SLAAC client to get a DNS server, but advertising one nothing
answers on is worse than advertising none. The caller passes the address `internal/dnsproxy` *actually
bound*. Having `Serve` re-resolve it independently could diverge from what the proxy bound — e.g.
if the link-local was still tentative when the proxy started.

## `Updater` — changing config without restarting

`Serve` takes an optional `*Updater`: a size-1, latest-wins channel of `Config`s. `Set` never
blocks and replaces an update `Serve` hasn't picked up yet, since only the newest config is
meaningful.

It exists because **cancel-then-restart is not a neutral way to change what's advertised**.
Cancellation is `Serve`'s *shutdown* path: it emits RFC 4861 §6.2.5's `RouterLifetime=0`
advertisement, and since the RDNSS option's lifetime tracks the router lifetime, an RDNSS
`Lifetime=0` with it. Every LAN client is told this router is going away and its DNS server is
unusable, moments before the replacement worker announces both again. `internal/lanprefix` used
to inflict exactly that flap on every DHCPv6-PD Renew (`docs/rfc-compliance-backlog.md` §1, now
resolved).

A new config that differs from the current one is advertised **promptly** rather than at the next
scheduled RA — still respecting §6.2.4's `MIN_DELAY_BETWEEN_RAS` floor between consecutive
multicast RAs. An identical config is ignored: nothing LAN clients would see differently.

## `Serve` timing (§6.2/§10)

One `select` loop over four things: a timer, the update channel, inbound solicitations, and `ctx`.

- **Unsolicited**: a fast initial burst (the first `MAX_INITIAL_RTR_ADVERTISEMENTS` = 3, each
  within `MAX_INITIAL_RTR_ADVERT_INTERVAL` = 16s, so a newly-attached host doesn't wait a full
  steady-state interval), settling into the jittered [198s, 600s] cadence of §6.2.4.
- **Solicited**: rate-limited to once per `MIN_DELAY_BETWEEN_RAS` = 3s, and delayed by up to
  `MAX_RA_DELAY_TIME` = 500ms so replies to a simultaneous burst don't synchronize.
- **Shutdown**: on `ctx` cancellation, one final best-effort `RouterLifetime=0` RA (§6.2.5).

`randInterval` picks **uniformly across the configured range**, which is RFC 4861's own
randomization rule — deliberately unlike RFC 3315 §14's jitter-around-a-base formula used
elsewhere in this repo.

### The `EADDRNOTAVAIL` retry

A send failing with `EADDRNOTAVAIL` means the interface has no usable source address yet — the
link-local is still DAD-tentative. This genuinely happens in minuteman's startup sequence: an XDP
attach can bounce the link, and the LAN address assignment lands immediately before `Serve`
starts. It used to kill the RA worker for good, leaving LAN clients with no SLAAC at all.

Now it retries on DAD's ~1s timescale (`tentativeRetryInterval`) instead of being fatal.
`SolicitRouters` shares the same retry (`sendRetryingTentative`) for exactly the same reason — it
fires right after `AttachWAN`'s forwarding flip, which can itself leave the WAN link's address
tentative.

## The socket (`transport.go`)

`Listen` hand-rolls a raw `AF_INET6`/`SOCK_RAW`/`IPPROTO_ICMPV6` socket via
`golang.org/x/sys/unix` — no `golang.org/x/net/icmp`, matching `pkg/netlink`'s no-external-library
philosophy — and sets up three things that each matter:

- joins the **All-Routers** multicast group, or multicast Router Solicitations never arrive at
  all;
- sets **both** hop limits to 255 (§6.1.2's anti-spoofing requirement on every NDP packet);
- installs an `ICMP6_FILTER` passing only Router Solicitation, so the read loop isn't woken by
  echo, NS/NA or MLD traffic. `ICMP6_FILTER`'s sockopt-name constant isn't exported by
  `x/sys/unix` on Linux, so it is vendored locally — the same rationale as `bpf/uapi/linux/*.h`.

`Solicitations()` returns a coalescing size-1 channel: a burst collapses to one pending signal,
which is all a caller needs ("at least one RS arrived since I last looked"). The channel closes
when the socket does, which is how `Serve` notices the `Conn` is finished.

`LinkLocalAddr(iface)` returns the interface's `fe80::/10` address **zoned with the interface**.
`cmd/minuteman` binds the DNS proxy to it and passes it straight back as `Config.RDNSSAddr`: a
router's link-local is explicitly a valid RDNSS entry (RFC 8106 §5.1), and unlike a global
address it exists regardless of which WAN provisioning model assigned this LAN its prefix, so
callers don't need to know which is active. The zone is local metadata only — the wire encoding
(`As16()`) drops it, as it must.

## `SolicitRouters` — why a router sends Router Solicitations

It exists for one specific moment: right after `pkg/datapath`'s `configureWANSysctls` enables IPv6
forwarding. That 0→1 transition makes the kernel purge every RA-learned default route
(`rt6_purge_dflt_routers`), and even with `accept_ra=2` the route only returns at the upstream
router's next *unsolicited* RA — potentially minutes, during which the WAN, and therefore the
datapath's own `bpf_fib_lookup`, has no route to the AFTR. Soliciting brings it back immediately.

It sends §6.3.7's host cadence (3 RSes, 4s apart, ~8s total) and only transmits — the kernel
receives and processes whatever RAs come back, so there is nothing to read or return.

## Testing

```sh
go test ./pkg/routeradvert/
```

`message_test.go`, `options_test.go` and `advertise_test.go` cover the marshalling and the timing
helpers. The raw sockets are exercised by the netns rig, where `mm-host` SLAACs an address out of
whatever this package advertises. See `test/netns/README.md`.
