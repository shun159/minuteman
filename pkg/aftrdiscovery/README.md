# pkg/aftrdiscovery

RFC 6334 AFTR discovery: a stateless DHCPv6 Information-Request fetches `OPTION_AFTR_NAME` and
`OPTION_DNS_SERVERS`, and the AFTR-Name is resolved to an IPv6 address via DNS — entirely
in-process, with no external DHCP or DNS client.

This is RFC 6334-specific logic layered on `pkg/dhcpv6`, the same way `pkg/prefixdelegation`
layers RFC 3633 on it. The generic client knows nothing about AFTR names; this package knows
nothing about softwires.

## Files

| File | Role |
| --- | --- |
| `discover.go` | `Discover`, `Result`, and the two sentinel errors |
| `dnsname.go` | RFC 1035 wire-format name decoding (package doc lives here) |
| `resolve.go` | AAAA resolution against the Reply's own DNS servers |

## `Discover(ctx, ex, replyTimeout)`

One Information-Request with an ORO for DNS servers, AFTR-Name and Information-Refresh-Time, run
through `ex` (a `dhcpv6.Exchanger`: minuteman's is `internal/dhcpv6client`), then a AAAA lookup of
the decoded name.

`replyTimeout` bounds **only the Information-Request phase**, not the DNS resolution that
follows. That split is what makes a timeout unambiguous: it means "nothing answered", reported as
`ErrNoReply`, rather than "something answered but the name wouldn't resolve". Zero or negative
keeps `dhcpv6.InformationRequest`'s RFC-correct unbounded retry.

`Result.RefreshInterval` is RFC 4242's refresh time (defaulting to §2's 24h when the server sends
none). It is **reported, not acted on** — periodic re-discovery is a caller-level policy
decision, and `internal/softwirectl`'s controller is where it happens. Contrast
DHCPv6-PD, whose renewal ladder `internal/pdlease` drives as a matter of course: a lease that is
never renewed actually expires and breaks LAN connectivity, whereas a stale AFTR reading merely
becomes stale.

## The two sentinel errors, and why one of them carries a partial result

```go
var ErrNoAFTRName = errors.New(...)  // returned *together with* a partial *Result
var ErrNoReply    = errors.New(...)  // returned with a nil Result
```

They describe genuinely different networks, and `cmd/minuteman` falls forward to HB46PP from
both — but sources the DNS servers HB46PP needs differently in each case:

- **`ErrNoAFTRName`** — the server answered, but its Reply carried no `OPTION_AFTR_NAME`. The ISP
  speaks DHCPv6 and simply doesn't advertise an AFTR that way. Everything else the Reply carried
  is still useful, so `Discover` returns a partial `Result` (DNS servers + refresh interval)
  *alongside* the error — the one case where both return values are non-nil, documented on the
  sentinel itself. HB46PP gets those resolvers.
- **`ErrNoReply`** — nothing answered within `replyTimeout`. There is no partial result: without
  a Reply nothing at all was learned, so a caller falling forward has to source resolvers
  elsewhere (in minuteman's case, from the DHCPv6-PD lease — which is why `run()` acquires that
  lease *before* AFTR discovery).

`ErrNoReply` exists as a named outcome rather than a bare timeout because networks that never
answer Information-Request are documented reality, not a hypothetical: two access tiers of the
NTT East FLET'S IPoE spec state outright that theirs doesn't (光クロス §4.4.2.1.2 and 光25G
§2.4.1.1.2 of 第三分冊) — and those are exactly the deployments HB46PP serves. Without the bound,
RFC 3315 §18.1.5's unbounded retry would make that an indefinite hang instead of a discovery
failure.

`Discover` also distinguishes its own bound expiring from the *caller* cancelling: both surface
as `context.DeadlineExceeded`, so it checks `ctx.Err()` to tell them apart and only reports
`ErrNoReply` for the former.

## Name decoding (`dnsname.go`)

`decodeDNSName` decodes one RFC 1035 §3.1 wire-format name — length-prefixed labels, terminated
by a zero-length label, which must consume the buffer **exactly** (trailing bytes are an error).

Compression pointers are **rejected, not followed**. RFC 3315 §8 disallows compression for domain
names embedded in DHCPv6 options, and there is no enclosing DNS message for a pointer to resolve
against anyway. The check rejects any length byte with either top bit set (`n&0xC0 != 0`), which
covers the compression prefix `11` as well as the `01`/`10` prefixes RFC 1035 leaves
reserved — a hostile server gets an error, not an interpretation.

## Resolution (`resolve.go`)

`resolveAFTR` looks the name up over `ip6` using a `net.Resolver` dialed against the DNS servers
from **the same DHCPv6 Reply** (RFC 6334's own model), falling back to the system resolver when
the Reply carried none. `dialServers` tries each server in order on port 53, ignoring the address
the resolver itself would have used. (`pkg/hb46pp/transport.go` has a mirror of this helper, for
the same reason: a VNE-specific answer must be looked up through VNE-provided resolvers.)

Multiple addresses → the first is used. RFC 6334 specifies no selection policy; `pkg/hb46pp`
takes the same stance.

A malformed DNS-servers option is not fatal — the AFTR name may still resolve via the system
resolver — so `Discover` drops it and continues.

## Testing

```sh
go test ./pkg/aftrdiscovery/     # dnsname_test.go
```

The wire decoder is unit-tested; the exchange itself is exercised end-to-end by the netns rig
with `MM_AFTR_DISCOVERY=dhcpv6` (the default), where Kea serves a real RFC 6334 `OPTION_AFTR_NAME`
that dnsmasq's DNS then resolves. `MM_AFTR_DISCOVERY=hb46pp` has Kea withhold option 64, which
is what exercises the `ErrNoAFTRName` path into `pkg/hb46pp`. See `test/netns/README.md`.
