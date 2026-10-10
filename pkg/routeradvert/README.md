# pkg/routeradvert

The subset of RFC 4861 (Neighbor Discovery) a CPE actually needs — no more:

- **LAN side**: the Router Advertisements carrying a Prefix Information Option, so LAN clients
  SLAAC an address (`BuildRA`), and their §6.2/§10 timing (`NextUnsolicitedInterval`,
  `ReplyDelay`, the constants). Sending them is `internal/radvd`'s: a molecule process per LAN
  interface, owning its raw ICMPv6 socket.
- **WAN side**: send Router Solicitations upstream, so the CPE's *own* host role gets a default
  route back promptly (`SolicitRouters`).

Not the full NDP message set: no Neighbor Solicitation/Advertisement (that's `pkg/ndproxy`), no
Redirects. The wire codec is **marshal-only** — this package never needs to decode an RA or an
RS body, only to notice that an RS arrived (`IsRouterSolicitation`).

Both `internal/lanprefix` and `internal/wanextend` decide a `Config` per LAN interface for
`internal/radvd` to advertise; what differs between them is `Config.OnLink`.

## Files

| File | Role |
| --- | --- |
| `message.go` | RA fixed header + `RouterSolicitation` framing (package doc lives here) |
| `options.go` | `PrefixInformation` (§4.6.2), `SourceLinkLayerAddress` (§4.6.1), RDNSS (RFC 8106) |
| `transport.go` | what an advertiser's socket needs: the multicast addresses, `SolicitationFilter`, `LinkLocalAddr` |
| `advertise.go` | `Config`, `BuildRA`, the §6.2/§10 timing |
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
bound*. Having the advertiser re-resolve it independently could diverge from what the proxy bound — e.g.
if the link-local was still tentative when the proxy started.

## Timing (§6.2/§10)

What `internal/radvd` schedules by:

- **Unsolicited** (`NextUnsolicitedInterval`): a fast initial burst (the first
  `MAX_INITIAL_RTR_ADVERTISEMENTS` = 3, each within `MAX_INITIAL_RTR_ADVERT_INTERVAL` = 16s, so a
  newly-attached host doesn't wait a full steady-state interval), settling into the jittered
  [198s, 600s] cadence of §6.2.4.
- **Solicited**: no sooner than `MinDelayBetweenRAs` = 3s after the last RA, and delayed by up to
  `MAX_RA_DELAY_TIME` = 500ms (`ReplyDelay`) so replies to a simultaneous burst don't synchronize.
- **Shutdown**: one final `RouterLifetime=0` RA (§6.2.5) -- `BuildRA` with lifetime 0, which
  withdraws the RDNSS server with the router.

The functions draw from a `*rand.Rand` they are given, so an advertiser written as a pure
behaviour keeps its own generator. `randInterval` picks **uniformly across the configured range**, which is RFC 4861's own
randomization rule — deliberately unlike RFC 3315 §14's jitter-around-a-base formula used
elsewhere in this repo.

### The `EADDRNOTAVAIL` retry

A send failing with `EADDRNOTAVAIL` means the interface has no usable source address yet — the
link-local is still DAD-tentative. This genuinely happens in minuteman's startup sequence: an XDP
attach can bounce the link, and the LAN address assignment lands immediately before advertising
starts. It used to kill the RA worker for good, leaving LAN clients with no SLAAC at all.

The advertiser retries on DAD's ~1s timescale (`TentativeRetryInterval`) instead.
`SolicitRouters` shares the same retry (`sendRetryingTentative`) for exactly the same reason — it
fires right after `AttachWAN`'s forwarding flip, which can itself leave the WAN link's address
tentative.

## What the advertiser's socket needs (`transport.go`)

`internal/radvd` opens a raw `AF_INET6`/`SOCK_RAW`/`IPPROTO_ICMPV6` socket per LAN interface, and
sets up three things that each matter: it joins the **All-Routers** multicast group
(`AllRoutersMulticast`), or multicast Router Solicitations never arrive at all; it sets **both**
hop limits to 255 (§6.1.2's anti-spoofing requirement on every NDP packet); and it installs
`SolicitationFilter()`, an `ICMP6_FILTER` passing only Router Solicitation. `ICMP6_FILTER`'s
sockopt-name constant (`ICMP6Filter`) isn't exported by `x/sys/unix` on Linux, so it is vendored
here -- the same rationale as `bpf/uapi/linux/*.h`.

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

`message_test.go`, `options_test.go` and `advertise_test.go` cover the marshalling, `BuildRA` and
the timing helpers; `internal/radvd`'s tests the scheduling. The raw sockets are exercised by the
netns rig, where `mm-host` SLAACs an address out of whatever is advertised. See `test/netns/README.md`.
