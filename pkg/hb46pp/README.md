# pkg/hb46pp

Client for **HB46PP** — the JAIPA-standardized "HTTP-Based IPv4 over IPv6 Provisioning Protocol"
([v6mig-1 spec](https://github.com/v6pc/v6mig-prov/blob/master/spec.md)), the VNE-agnostic
discovery layer many Japanese VNEs use instead of DHCPv6 AFTR-Name.

The protocol is two steps: a DNS TXT lookup on the well-known `4over6.info` locates the VNE's
provisioning server, and an HTTP(S) GET to it returns JSON describing which IPv4-over-IPv6
migration technologies the VNE offers and with what parameters.

Like `pkg/aftrdiscovery`, this package runs entirely in-process (stdlib resolver and HTTP client)
and is **discovery logic only** — what to do with the returned parameters is the caller's policy
decision. It is why minuteman needs no per-VNE configuration.

## Files

| File | Role |
| --- | --- |
| `discover.go` | `Discover`, `Config`, `Result` (package doc lives here) |
| `txt.go` | the `4over6.info` TXT lookup and record parsing; `ErrNotProvisioned` |
| `request.go` | `ClientInfo` validation and query-string construction |
| `response.go` | JSON decoding, the 307 redirect loop, `RefreshInterval` |
| `transport.go` | the IPv6-only HTTP client and the resolver-dialed-at-servers helper |
| `retry.go` | `RetryDelay` — the spec's jittered backoff windows by failure class |

## Discovery: `4over6.info` (`txt.go`)

A record looks like:

```
v=v6mig-1 url=https://vne.example.jp/rule.cgi t=b
```

The answer is **VNE-specific** — each VNE serves its own record from its own resolvers — which is
why `Config.DNSServers` should be the WAN-learned ones, never a public resolver.

`t=` is enforced as a scheme constraint per spec §3.2's four connection methods:

| `t=` | Meaning | Allowed URL scheme |
| --- | --- | --- |
| `b` | certificate-validated | `https` only |
| `a` | no certificate validation | `http` **or** `https` |

`t=a` permitting https is deliberate, not sloppy: the spec's only directional rule is that a
plain-http URL must be paired with `t=a`, not the converse — so `t=a` + https means "https
without verifying the certificate", which `ServerInfo.ValidateCert` carries through to
`InsecureSkipVerify`. The VNE asked for that itself.

NXDOMAIN, NODATA, or only unparseable records all yield the distinct sentinel
**`ErrNotProvisioned`** — "this VNE doesn't do HB46PP" as opposed to a transient failure. The
distinction is what makes `RetryDelay`'s hours-long backoff appropriate for it and not for
everything else.

## Request (`request.go`)

`ClientInfo` carries the spec §3.2 query parameters, each with its own format rule enforced
before a request goes out: `vendorid` (6 hex digits + optional suffix), `product`, `version`
(digits and underscores only — no periods), a closed set of `capability` values, and an optional
64-hex-char `token` echoed from a previous response.

Parameters are emitted in the spec's **example order** (vendorid, product, version, capability,
token) rather than `url.Values`' alphabetical order, so requests look like the ones real deployed
servers were tested against.

The spec's optional `user`/`pass` parameters for VNE-authenticated service are not sent —
minuteman has no credential store — which per the `auth` field's semantics just means the server
may withhold auth-gated extras.

## Response (`response.go`)

`Provisioning` decodes the body. **Only `dslite` gets a typed struct**, since that is the only
technology minuteman implements; `map_e`, `map_t`, `lw4o6`, `464xlat` and `ipip` are preserved as
`json.RawMessage` so a future implementation can add its typed struct without re-fetching or
re-deriving anything.

Three decoding decisions worth knowing:

- `order: []` is spec-valid ("no method available for this client") and is distinguished from the
  field being **absent** (spec-invalid) via Go's own nil-vs-empty-slice `json.Unmarshal`
  behavior — no wire-type indirection needed.
- A body over `maxResponseBytes` (1 MiB) is **rejected outright**, not silently
  truncated-and-decoded. Any non-whitespace data after the JSON object is rejected too.
- `auth: "bad"` is a decode-level error (authentication failed), not a field for the caller to
  inspect.

`RefreshInterval()` returns the `ttl` field capped at the spec's 7-day maximum, or — when `ttl`
is absent or nonsensical — a **random** duration in the spec's 20–24h default window, so a fleet
of CPEs that provisioned together doesn't re-query together.

### The 307 loop

`fetchProvisioning` follows **only** the spec's 307-to-another-server redirect. `http.Client`'s
default policy also follows 301/302/303/308, meanings this protocol never defines, so
`newHTTPClient` disables it entirely via `CheckRedirect` and this loop (capped at `maxRedirects`)
is the sole redirect handling that happens. A redirect away from https is rejected when the
original record was `t=b` — a certificate-validated connection must not silently downgrade
partway through.

403/404 get a specific error, since the spec assigns them a meaning: the server doesn't recognize
the request's source address as one of its subscribers.

## Transport (`transport.go`)

The spec requires IPv6-only access, and this is where that is enforced rather than assumed:
hostnames resolve via **AAAA only**, dials are **`tcp6` only**, and an address literal that isn't
IPv6 is refused before dialing. `dialServers` mirrors `pkg/aftrdiscovery`'s unexported helper of
the same name — every lookup this package performs (the TXT record, the provisioning server's
AAAA, the AFTR name's AAAA) goes through `Config.DNSServers` in order.

## Retry policy (`retry.go`)

`Discover` is **single-shot**. `RetryDelay(err)` maps a failure to the spec §3.4 backoff window
so the retry *policy* stays with the caller — the same reported-not-acted-on stance
`pkg/aftrdiscovery` takes on its refresh interval:

| Failure | Window |
| --- | --- |
| `ErrNotProvisioned` | 1–3 h |
| transient DNS (`*net.DNSError`) | 1–10 min |
| HTTP / JSON | 10–30 min |

Each is a uniformly random point in its window, so CPEs that failed together don't retry
together.

`cmd/minuteman` paces its retry loop with this — with one deliberate exception: a failure reached
*through* `aftrdiscovery.ErrNoReply` is capped at 5 minutes, because there the hours-long
`ErrNotProvisioned` verdict would have been reached without any evidence from DHCPv6 about what
kind of network this even is.

## Not yet implemented

The migration technologies other than DS-Lite. The raw parameter objects are already preserved,
so adding one means: a typed struct here, its datapath, and extending `cmd/minuteman`'s
capability request beyond the current dslite-only policy.

## Testing

```sh
go test ./pkg/hb46pp/
```

Extensively unit-tested (TXT parsing, request validation, JSON decoding, the redirect loop, the
IPv6-only dialer) against fakes — `Config`'s unexported `resolver`/`httpClient` fields exist for
exactly that. End-to-end coverage comes from the netns rig with `MM_AFTR_DISCOVERY=hb46pp`, where
dnsmasq serves the discovery TXT record pointing at a `python3 -m http.server` in `mm-isp`
serving the provisioning JSON as a static `rule.cgi`. See `test/netns/README.md`.
