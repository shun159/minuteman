# internal/dhcpv4server

The LAN-side DHCPv4 server minuteman runs behind `-dhcpv4`, as a
[molecule](https://github.com/shun159/molecule) supervision tree: one process per `-lan` interface,
owning that interface's packet socket and its lease pool. The protocol -- messages, options, the
`Pool`, `Handle`, framing -- is `pkg/dhcpv4`'s; this package is the process around it.

```
dhcpv4 (one_for_one)
├── dhcpv4 <iface>   genserver: the interface's AF_PACKET socket and Pool
└── ...
```

## Start

A child's start builds the interface's `Pool` (`dhcpv4.NewPool` validates the subnet), then opens a
cooked `AF_PACKET` socket with molecule's `net/socket`: `socket.Open` runs `socket(2)` and a setup
that attaches `dhcpv4.Filter` (UDP to port 67) *before* binding to the interface, so no unfiltered
packet is ever queued. The socket is passive and owned by the supervisor until the server owns it,
then armed `Once`. Any failure fails the tree's start, so a bad `-dhcpv4` configuration fails
minuteman's startup rather than surfacing in a log line.

## The server

A genserver whose state is the interface's `Pool`. Each request arrives as a `socket.DataMsg`;
`answer` parses it (`dhcpv4.ParseRequest`), runs `dhcpv4.Handle` on a **clone** of the pool -- the
behaviour must not change the state it is given -- and frames the reply (`dhcpv4.Frame`) for the
client's link-layer address, a `syscall.SockaddrLinklayer`. The reply goes out with
`SendActiveEffect(..., socket.Once)`, which also asks for the next request: one at a time, the rest
waiting in the kernel. A pool clone costs the size of a home LAN's leases, a few hundred at most.

Leases are kept by the clock: `now` is a field, which molecule fills with the process's clock
(`actor.Clocked`) -- `time.Now`, or gensim's virtual one -- and tests set.

A failed send is logged (the client retransmits); a failed read stops the server, and its supervisor
starts it again, with a fresh pool -- holding the leases kept, if any.

## Leases kept across restarts

With `-state-dir`, each interface's committed leases are kept in a
[kvs](https://github.com/shun159/molecule/tree/master/kvs) table, `<state-dir>/dhcpv4/<iface>`, by
client ID. `cmd/minuteman` opens the tables (`OpenLeases`) and hands them to `Spec`; they outlive
the tree, and are closed once it has stopped, so a server restarted by its supervisor finds its
table open.

- **Start**: the child's start puts the kept leases back into the new pool (`Pool.Restore`) and
  deletes those it refuses: expired while the CPE was down, or no longer in the pool.
- **Writes**: after each request, `keep` compares the client's committed lease before and after
  (`Pool.Committed`). A lease committed or renewed is put with `PutEffect`, one that ended
  (RELEASE, DECLINE) deleted with `DeleteEffect`. Offers are not kept: they last 60s.
- **ACK after the disk**: a reply granting a lease is held, its socket armed for the next request
  meanwhile, until the `kvs.Durable` of the put arrives: an ACK is never lost to a restart that
  would forget it. A put that fails is logged and the reply sent all the same -- a client
  answered matters more than a lease remembered.
- **Expiry**: the table knows each lease's expiry (`Expires`), and every minute the server deletes
  the expired ones with `ExpireEffect`, by its own clock. The pool frees an expired lease by
  itself; this keeps the table from growing with the leases of clients long gone. A lease renewed
  meanwhile stays.

A client rebooting after the CPE did gets its INIT-REBOOT ACKed at once, rather than silence and a
fresh DISCOVER.

## Testing

`go test` calls `answer` directly: a DISCOVER gets an OFFER framed to the broadcast address it asked
for, the pool given left as it was; a non-DHCP packet gets nothing; an invalid subnet fails the
tree's start before any socket opens. `pkg/dhcpv4`'s own tests cover the protocol. End to end, the
netns rig's `MM_DHCPV4=1` has a real `dhclient` lease an address from it.
