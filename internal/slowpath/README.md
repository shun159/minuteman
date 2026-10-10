# internal/slowpath

Owns the kernel `ip6tnl` companion device that gives the DS-Lite datapath softwire
**reassembly** and a **fragmentation fallback** (RFC 6333 §5.3) without either being done in
XDP.

The XDP fast path handles every whole, in-MTU softwire packet itself, and since the in-XDP
outer-IPv6 fragmenter landed (`internal/fragpath`) it handles most oversized outbound packets
too. What is left over it `XDP_PASS`es rather than dropping, and this package is what makes
that hand-off land somewhere useful:

| Case | Counter | What the kernel then does |
| --- | --- | --- |
| Fragmented softwire IPv6 inbound | `STAT_DECAP_REASM_PASS` | reassembles, *then* the ip6tnl decapsulates — §5.3's "reassembly MUST happen before decapsulation" |
| Oversized outbound the XDP fragmenter's guards rejected | `STAT_ENCAP_FRAG_SLOW` | fragments the **inner** IPv4 to the device MTU, ip6tnl encapsulates each piece |
| Decapped inner too big for a non-DF LAN egress | `STAT_DECAP_FRAG_SLOW` | same, toward the LAN |

Only the first of those is §5.3 conformance. The other two fragment the inner IPv4 rather than
the outer IPv6 — a reachability fallback, tracked as the residual note in
`docs/rfc-compliance-backlog.md` §1. See `internal/fragpath` for the guards that decide which
oversized packets get the conformant in-XDP treatment and which fall back here.

A side benefit of the IPv4 default route this package installs: the kernel can answer ICMPv4
Time Exceeded for an inner TTL expiring on the *outbound* path. (The route is also why the
decap path drops an inner IPv4 that the FIB resolves back toward this tunnel —
`STAT_DECAP_MARTIAN` — rather than turning the decap path into a reflector.)

## The device

`mm-dslite0`, `local = B4 address`, `remote = AFTR`, mode `ipip6`, `encaplimit none`, plus an
IPv4 default route through it (the softwire is the B4's only IPv4 path). The name is fixed so
a restart can find and replace a device an earlier crashed run left behind.

`tunnelMTU(softwireMTU)` = `max(softwireMTU, 1280) - 40`. The 1280 floor deliberately applies
to the *softwire* MTU, not to the result. Flooring the result instead would give the kernel a
1280-byte device MTU for a path that just reported 1280 — and every fragment it then made
would leave as a 1320-byte outer packet the path can only drop again. That is exactly the case
a learned path MTU is most likely to be: 1280 is what nested tunnels report, and
`learn_tunnel_pmtu` floors its own readings there per RFC 8201 §4.

## Lifecycle

`New(wanMTU)` opens the netlink socket the `Tunnel` uses for its lifetime and records the
derived MTU; it does not create the device yet.

`Ensure(b4, aftr)` removes any stale `mm-dslite0`, creates and ups the device, and adds the
default route. **Fail-fast** — a home CPE has no other IPv4 path, and a missing `ip6_tunnel`
kernel module surfaces as `EOPNOTSUPP` with an explicit hint rather than as silent
degradation.

`SetEndpoints(b4, aftr)` repoints the device in place (changelink, keeping the route) after an
AFTR migration's cutover or a dynamic-B4 hard switch.

`SetSoftwireMTU(mtu)` re-derives the device MTU when the datapath learns a narrower softwire
path MTU from an inbound ICMPv6 Packet Too Big (RFC 2473 §8). This matters because the device
MTU is what the kernel fragments the inner IPv4 to on every fallback path: left at the WAN
figure it would keep handing a narrow path pieces it can only drop again. A no-op when the
derived MTU is unchanged.

Both mutators are **best-effort** in a way `Ensure` is not: the fast path has already adapted
by the time either is called (it is already carrying whole packets on the new softwire, and
encap clamps against the learned MTU per packet), so a transient failure only lags the
fallback, and `cmd/minuteman` logs it rather than dying.

`Close()` deletes the device — which takes its default route with it — best-effort, and closes
the socket. A device that outlives the process is replaced by the next run's `Ensure` anyway.

## Concurrency

The mutating methods serialize against each other under a mutex. Two independent goroutines
legitimately drive this device: `internal/softwirectl` repoints its endpoints, and
`internal/tunnelpmtu` resizes it. The netlink socket underneath is a single-writer request/reply
channel (one `Send`, one `Recvfrom`, matched by an incrementing sequence number), so
unsynchronized callers would consume each other's ACKs and report failures for requests that in
fact succeeded.

This is the one structural difference from `internal/wanextend.HostRoutes` and
`internal/fragpath`, whose otherwise identical single-long-lived-socket shape needs no lock
because each has a single caller.

## Wiring

`cmd/minuteman` creates the tunnel right after `SetB4Config` for **every** run, static or
dynamic, and hands it to `internal/softwirectl` (the single owner of the live softwire endpoints)
and to `internal/tunnelpmtu`. Its `defer Close()` runs after the applications stop — so the
processes that repoint and resize it have stopped — but before `dp.Close()`.

## Testing

No `go test`: this package is entirely netlink I/O against real kernel devices. It is
exercised by the netns rig, most directly with `MM_SOFTWIRE_FRAG=1` (a hand-crafted fragmented
softwire packet inbound via `send-softwire-fragments.py`) and `MM_TUNNEL_ICMP=1` (which narrows
the ISP↔AFTR core link to draw a real Packet Too Big, then asserts the learned path MTU
reached both the XDP fragmenter and this device's MTU). See `test/netns/README.md`.
