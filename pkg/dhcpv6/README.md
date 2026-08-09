# pkg/dhcpv6

A generic, **stdlib-only** DHCPv6 client: the RFC 3736 stateless exchange AFTR discovery needs
and the RFC 3315 stateful exchanges a prefix-delegation client needs, with no external DHCP
process and no third-party library.

It is deliberately option-agnostic. `Solicit`/`Request`/`Renew`/`Rebind`/`Release` take and
return plain `Options`/`*Message`; they know nothing about IA_PD or AFTR-Name. Decoding those is
the consuming package's job (`pkg/prefixdelegation`, `pkg/aftrdiscovery`), which is what lets
this package stay a DHCPv6 client rather than a minuteman component.

## Files

| File | Role |
| --- | --- |
| `message.go` | `Message` (type + 3-byte XID + options), `ParseMessage`, `MarshalBinary` |
| `options.go` | `Option`/`Options` TLV codec, option builders, `ParseSubOptions` |
| `duid.go` | DUID-LL from a MAC |
| `retransmit.go` | pure RFC 3315 §5.5/§14 timing constants and formulas |
| `transport.go` | socket binding, `sendAndWait`, the per-interface exchange lock |
| `client.go` | `runExchange`, `validateServerMessage`, and the exported exchanges |

## Where the option-decoding line is drawn

Option **codes** for options a consumer decodes itself live here as bare constants
(`OptionIAPD`, `OptionIAPrefix`, `OptionAFTRName`) — but their decoding does not.

The exception is an option that is both generic DHCPv6 *and* has more than one consumer in this
repo; decoding it once here beats duplicating it per consumer. Two qualify, and both get an
`Options` accessor: `InformationRefreshTime()` (RFC 4242) and `DNSServers()` (RFC 3646, read by
both `pkg/aftrdiscovery` and `pkg/prefixdelegation`). `DNSServers` distinguishes absent from
malformed — a caller that only wants "usable servers, if any" can treat both alike, but an option
the server *did* send and this client couldn't parse is worth logging, where an absent one is
routine.

`ParseSubOptions` exists because IA_PD's nested suboption format is byte-for-byte identical to
top-level message options (RFC 3315 §22.1), so `pkg/prefixdelegation` decodes IAPREFIX/STATUS_CODE
with the same parser rather than writing a second one.

## DUID

`NewDUIDLL(hardwareType, mac)` builds a DUID-LL (RFC 3315 §9.4), regenerated fresh on every run
rather than persisted to disk. It is a pure function of hardware type + MAC, so regeneration
yields the *same* identifier — unlike DUID-LLT (§9.3), which embeds a timestamp and would look
like a new identity every time. Same rationale as `pkg/prefixdelegation`'s fixed `clientIAID`:
a stable identity is what gets the same delegated prefix back across a restart, avoiding LAN
renumbering.

## Retransmission (`retransmit.go`)

Pure RFC 3315 §14 timing, no I/O — an initial jittered delay, then `RT = 2·RTprev + RAND·RTprev`,
capped at each exchange's MRT.

The cap is the part worth calling out: on reaching MRT the timeout is set to `MRT + RAND·MRT`,
i.e. jitter is re-applied **around the ceiling** rather than clamped to a fixed value. Once
steady state is reached — hour-long retries against `InfMaxRT`, say — retransmissions keep
varying ±10% instead of converging on one fixed interval, which preserves RAND's
anti-synchronization purpose for exactly the long-running case where a fleet of CPEs rebooting
together would matter most.

| Exchange | Initial delay | IRT | MRT | MRC |
| --- | --- | --- | --- | --- |
| Information-Request | ≤1s | 1s | 3600s | — (unbounded) |
| Solicit | ≤1s | 1s | 3600s | — (unbounded) |
| Request | none | 1s | 30s | 10 |
| Renew | none | 10s | 600s | — |
| Rebind | none | 10s | 600s | — |
| Release | none | 1s | — | 5 |

Only Request and Release have a maximum retransmission *count*: §18.1.1 says an unanswered
Request should restart at Solicit, and §18.1.6 says a client stops using a released binding
locally whether or not the Release was ever acknowledged (so `Release` treats exhaustion as
success). Renew and Rebind are unbounded here but bounded in practice by the caller wrapping
`ctx` with a deadline at T2 / the shortest remaining valid lifetime — this package does not
track lease timing.

**Information-Request has no bound at all**, which is RFC-correct (§18.1.5 sets neither a maximum
count nor a maximum duration) and right wherever the network answers eventually. A bound is a
caller's policy for networks that never will; `pkg/aftrdiscovery.Discover`'s `replyTimeout` is
where minuteman applies one, and `ErrNoReply` is the outcome.

## Transport (`transport.go`)

Two decisions carry the file:

**`ListenUDP`, never `DialUDP`.** A connected socket only accepts datagrams from the address it
is connected to — but the server's Reply comes unicast from the *server's* address, not from the
multicast destination the request went to. A connected socket would silently drop every reply.
Binding to a zone-qualified link-local address additionally fixes the outgoing interface for the
multicast request: on Linux, binding to a link-local sets the socket's bound device, which route
lookups consult before `IPV6_MULTICAST_IF`, so no explicit multicast-interface sockopt is needed.

**A per-interface exchange lock (`lockWAN`).** Every exchange binds the same
`[link-local%iface]:546` with no `SO_REUSEADDR`, so two concurrent exchanges on one interface
would collide with `EADDRINUSE`. minuteman genuinely runs them concurrently — a long-lived
DHCPv6-PD maintenance loop alongside periodic AFTR re-discovery, both on the WAN — so they take
turns here. The lock honours `ctx`, so a Renew waiting behind a long-running AFTR discovery can
still give up at its own T2.

`sendAndWait` returns `(nil, nil)` on a plain timeout (the caller retries with a new RT) and
discards anything that isn't a reply of the expected type with a matching XID. The expected type
is a parameter because Solicit expects an **Advertise**, not a Reply.

## The exchange loop (`client.go`)

`runExchange` is the single RFC 3315 §14 retransmission loop behind every exported function.
`validateServerMessage` is RFC 3315's general validation rule (restated for stateless service in
RFC 3736 §4): an Advertise/Reply must carry `OPTION_SERVERID`, and an echoed `OPTION_CLIENTID`,
if present, must match ours. A message that fails validation is **discarded and the exchange
keeps retrying** — RFC 3315 is explicit that one bad message does not fail the exchange.

`Solicit` takes the first valid Advertise rather than collecting several over a window and
picking by preference (§17.1.3). That is the common and correct behavior on a residential link
with a single upstream delegating router.

## Testing

```sh
go test ./pkg/dhcpv6/
```

`message_test.go`, `options_test.go`, `retransmit_test.go` and `transport_test.go` cover the wire
codec and the timing formulas with no sockets. Live behavior is exercised through
`pkg/aftrdiscovery` and `pkg/prefixdelegation` in the netns rig (Kea on `mm-isp`), see
`test/netns/README.md`.
