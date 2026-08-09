# pkg/dhcpv4

The LAN-side DHCPv4 **server** (RFC 2131/2132) minuteman runs behind `-dhcpv4`, handing LAN
clients the private IPv4 addresses the DS-Lite softwire carries — the counterpart to the WAN-side
softwire that actually moves that traffic.

Server only, and only the case a home CPE serves: directly attached, one subnet per interface.
Deliberately **not** supported — a BOOTP relay request (`giaddr != 0`) is rejected rather than
mis-answered, since a relayed reply must go back to the relay agent on the server port; no
multi-subnet shared networks; no persistence across restarts (an in-memory pool, like the rest of
minuteman's state).

## Files

Same pure-vs-I/O split as `pkg/ndproxy`:

| File | Role | Pure? |
| --- | --- | --- |
| `message.go` | BOOTP header + magic cookie framing (package doc lives here) | yes |
| `options.go` | option TLV codec | yes |
| `lease.go` | `Pool` — the address allocator | yes |
| `handler.go` | `handle` — request → reply (or silence) | yes |
| `packet.go` | raw `AF_PACKET` I/O | no |
| `server.go` | `New`, `Serve`, per-interface goroutines | no |

`Options.Marshal` splits a value past 255 bytes across repeated option instances per RFC 3396,
rather than truncating a length byte.

## Why `AF_PACKET` and not a UDP socket

A DHCP server can't use an ordinary UDP socket cleanly. It must reply to a client that has **no
IP address yet** (and so no ARP entry the kernel could resolve), honour the client's broadcast
flag, and know which LAN interface a broadcast arrived on.

So, like `pkg/ndproxy`, it uses a cooked `AF_PACKET` socket (`SOCK_DGRAM`, payload starting at the
IP header) bound to one interface: received frames are parsed as IPv4/UDP in Go, and replies are
built as raw IPv4+UDP (checksums included) and sent with an **explicit destination MAC** — the
client's `chaddr`, or broadcast — via `sendto`, with the kernel supplying the Ethernet header from
the `sockaddr_ll`. A classic-BPF filter (UDP dport 67) keeps all other traffic out of userspace.

> The datapath had to change before any of this could receive a packet: see
> `xdp_dslite_encap`'s `is_non_unicast_dst` bypass, which stops a limited-broadcast DISCOVER from
> being wrapped into the softwire — a point-to-point softwire must never carry one.

## `Pool` (`lease.go`)

The allocator for one LAN subnet. Pure — every method takes an explicit `now time.Time` instead of
reading the clock, like `pkg/ndproxy`'s `proxyState` — and in-memory only. `NewPool` excludes the
network, broadcast and server addresses from allocation.

Three things it does that a naive pool wouldn't:

- **Offered ≠ committed.** `Offer` holds an address for only `offerHoldTime` (60s); `Commit`
  holds it for the full lease. A DISCOVER that never becomes a REQUEST — a client that chose
  another server, went away, or a spoofed one — therefore can't tie up an address for a whole
  lease. `CancelOffer` returns it immediately when a REQUEST reveals the client picked someone
  else. A bound client's DISCOVER can never silently *shorten* its own lease.
- **DECLINE can't be weaponized.** `Decline` quarantines an address only if the declining client
  actually held it, so a client can't poison the pool with addresses it was never given — and the
  quarantine is bounded (`declineQuarantine`, 1 hour), not permanent, so a transient conflict
  doesn't remove an address for the process's lifetime.
- **Allocation prefers stability**: the address the client already holds, then a valid in-subnet
  requested address if free, then the lowest free address.

## `handle` (`handler.go`)

Pure: the only state it mutates is the `Pool`, and it reads the clock only through `now`. It
returns the reply to send, or **nil to stay silent**.

It distinguishes RFC 2131 §4.3.2's three DHCPREQUEST substates by which of server-identifier /
requested-IP / `ciaddr` the client set, and validates the server-id on RELEASE and DECLINE.

The important rule: **a REQUEST is ACKed only for an address this server actually offered or
leased to that client.** A REQUEST from a client it has no record of — including a returning
client's INIT-REBOOT after a restart wiped the in-memory pool — gets *silence*, not an ACK of a
free address. That is what lets independent DHCP servers coexist on one segment; the client falls
back to DISCOVER and gets a proper offer.

`siaddr` is deliberately left zero: it is the next-bootstrap-server field, not the server
identifier (option 54 carries that), and setting it would advertise this CPE as a boot server it
isn't. A NAK is broadcast, since the client's notion of its own address is exactly what's being
rejected.

## `InterfaceConfig`

| Field | DS-Lite meaning |
| --- | --- |
| `ServerIP` | the CPE's own LAN IPv4 — the server id and the offered router |
| `Subnet` | from `-lan`'s `/prefixlen` (default `/24`) |
| `DNSServers` | option 6; normally `ServerIP` itself, so LAN DNS goes to `-dns-proxy` and over IPv6 rather than through the softwire. Empty omits the option — `cmd/minuteman` declines to advertise a resolver that wouldn't answer |
| `MTU` | option 26; the **DS-Lite-adjusted** MTU — WAN MTU minus the 40-byte tunnel overhead — so clients size packets to fit the softwire. 0 omits it |
| `LeaseTime` | |

## `New` then `Serve` (`server.go`)

`New([]InterfaceConfig)` validates every pool and opens every socket **synchronously**, so an
invalid subnet, a missing interface or a socket/filter failure fails minuteman's startup instead
of surfacing only in a background log line. On any failure every already-opened socket is closed.

`Serve(ctx)` runs one goroutine and one `Pool` per interface. A worker's runtime **read error is
propagated, not swallowed** — a single interface's DHCP dying is surfaced — while the read errors
that closing the sockets on shutdown provokes are suppressed via a `shuttingDown` flag. `conn` is
an interface so a fake can exercise that error handling without a raw socket.

## Testing

```sh
go test ./pkg/dhcpv4/
```

The most thoroughly unit-tested package in the repo: the codec, the pool's expiry/quarantine/
offer-vs-commit rules, and every handler substate, all with no sockets. `server_test.go` uses the
fake `conn` for the error-propagation paths.

End-to-end, the netns rig's `MM_DHCPV4=1` toggle has `mm-host` run `dhclient` against minuteman
(a real DORA) and asserts it got the pool's first address, installed the default route via the
supplied router, and applied the DS-Lite-adjusted MTU. See `test/netns/README.md`.
