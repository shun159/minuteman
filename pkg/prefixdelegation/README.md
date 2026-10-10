# pkg/prefixdelegation

DHCPv6 Prefix Delegation (RFC 3633 / RFC 9915) on top of `pkg/dhcpv6`'s stateful exchanges:
acquire a delegated IPv6 prefix and keep it alive, in-process, with no external DHCP client.

It mirrors `pkg/aftrdiscovery`'s shape — RFC-specific option decoding plus an orchestration
entry point over a generic client — with one addition: the exchanges that **maintain** the lease
(`Renew`, `Rebind`, `Release`) and the times of its renewal ladder. Climbing the ladder — waiting
for each step, applying each new lease — is `internal/pdlease`'s, a molecule process.

What to *do* with the delegated prefix — carving a `/64` per LAN interface, assigning it,
advertising it — is `internal/lanprefix`, not this package.

## Files

| File | Role |
| --- | --- |
| `options.go` | `IA_PD` / `IAPREFIX` / `STATUS_CODE` codec (package doc lives here) |
| `lease.go` | `Lease`, `clientIAID`, the outgoing IA_PD rebuild |
| `acquire.go` | `Acquire`, `usableIAPD` validation, the ORO |
| `renew.go` | `Renew`, `Rebind`, `Release`, and the ladder's times: `RenewAt`, `RebindAt`, `ExpiresAt` |
| `timers.go` | `effectiveTimers` — what to do when the server sends T1/T2 = 0 |

`options.go` decodes IA_PD's nested suboptions with `dhcpv6.ParseSubOptions`, since the nested
TLV format is byte-for-byte identical to top-level DHCPv6 options.

## Identity

`clientIAID` is a **fixed** constant, not random and not derived per-run (e.g. from the WAN
ifindex, which can change across reboots on some systems), so the server has the best chance of
handing back the same prefix after a restart and the LAN doesn't renumber. Same rationale as
`pkg/dhcpv6`'s stable DUID-LL.

## `Acquire` and the validation gate

`Acquire` drives the full Solicit → Advertise → Request → Reply exchange and **blocks, retrying,
until it succeeds or `ctx` is cancelled** — there is no LAN prefix to assign without one, the
same stance `aftrdiscovery.Discover` takes.

Every server message passes `usableIAPD` first, and anything it rejects means "discard and
retry", never "fail the exchange" (RFC 3315's general validation rule). It enforces:

- the IA_PD is present, decodes, and reports no failure status;
- **per-prefix**, RFC 9915 §21.22's MUST: a prefix whose preferred lifetime exceeds its valid
  lifetime is discarded. Individually, as the MUST says — dropping the whole IA_PD would be
  wrong, and keeping such a prefix would poison the timers derived from lifetimes below;
- the T1 > T2 > 0 combination §21.21 calls invalid — the option is discarded, which, being the
  only IA_PD in play, becomes a retry.

### The DNS-servers ORO

Every exchange in this package sends an ORO for `OPTION_DNS_SERVERS`. That has nothing to do with
the delegation — it is there because on a network that doesn't answer Information-Request, this
stateful exchange is the **only** DHCPv6 source of a resolver at all, and `cmd/minuteman`'s
HB46PP fallback needs one to look anything up. Asking costs a handful of bytes on two messages
and a server free to ignore it.

Consequently a *renewal* takes its DNS servers from its own Reply rather than inheriting the
previous lease's: the ORO went out with it too, so silence there is the server declining to
answer a question it was asked, not a question that went unasked.

## The renewal ladder (`renew.go`)

```
RenewAt (T1) ──► Renew  (deadline: RebindAt, T2)
                   ├─ ok ──► the new lease
                   └─ fail ──► Rebind  (deadline: ExpiresAt, the shortest valid lifetime)
                                  ├─ ok ──► the new lease
                                  └─ fail ──► Acquire (blocks) ──► the new lease
```

Each stage's deadline is the point the RFC says that stage stops being valid: Renew until T2
(§18.1.3), Rebind until the binding's shortest valid lifetime (§18.1.4). `pkg/dhcpv6` deliberately
doesn't know about lease timing, so `Renew` and `Rebind` apply these deadlines themselves, as
`ctx` deadlines. Each is one exchange; the ladder around them, and what a new lease means for the
LAN, are `internal/pdlease`'s (and `internal/lanprefix`'s).

`Release` (§18.1.6) is bounded by its `ctx` only: a client stops using a binding locally whether
or not the server ever acknowledges, so a caller shutting down bounds it short and logs a failure
rather than waiting it out.

## `effectiveTimers` — the T1/T2 = 0 problem

This is the subtlest part of the package, and it is a real bug fixed, not a hypothetical.

A server sends T1 and/or T2 as **0** to leave that timer to the requesting router's discretion
(RFC 9915 §21.21). Taken literally, 0 means "renew immediately, forever" — a renew storm at the
speed of the exchange RTT against any server that sends it. §14.2 is what bounds that discretion:
a client left to choose MUST avoid message storms and in particular MUST NOT transmit
immediately.

`effectiveTimers` resolves a delegated 0 into §21.21's own recommended ratios — **0.5×** and
**0.8×** of the shortest *preferred* lifetime — then applies three guards:

- a **floor** of `minDerivedT1` = 1 minute. §14.1 is what puts a number on "storm" (rate-limit
  transmissions, suggested default 20 messages in 20 seconds); a minute between renewals sits far
  below that and is still far more often than any real delegation needs. It bounds only derived
  values — a non-zero server T1 is used verbatim however small, since §21.21 makes that a MUST.
- a **ceiling** at the shortest *valid* lifetime. A Renew scheduled past the binding's own death
  can only fail into a full re-Acquire — more messages than renewing in time — so the ceiling
  serves the same anti-storm purpose the floor does.
- **ordering**: T1 ≤ T2 whichever of the two the server did pin, so the Renew-then-Rebind ladder
  stays meaningful. An infinite (0xffffffff) preferred lifetime means never renewing, and so
  never rebinding either.

Outgoing IA_PDs zero their own T1/T2 (§21.21's client-side SHOULD; the server ignores them
regardless). Echoing the lease's own timers back would be doubly wrong now that they may be
values *this client* derived rather than ones the server chose.

## Testing

```sh
go test ./pkg/prefixdelegation/
```

`options_test.go`, `lease_test.go`, `acquire_test.go` and `timers_test.go` cover the codec, the
validation gate and every branch of the timer derivation with no sockets.

The netns rig's **`MM_PD_ZERO_TIMERS=1`** mode is the regression test for the storm: Kea delegates
with T1=T2=0 on short lifetimes, and the smoketest waits out a real renewal, then asserts both
that a renewal happened *and* that the number of lease applications stayed within what
`minDerivedT1` allows. See `test/netns/README.md`.
