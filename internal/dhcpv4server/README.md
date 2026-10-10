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

Leases are kept by the clock, which a behaviour has no way to read: `now` is a field, `time.Now` in
production and fixed in tests.

A failed send is logged (the client retransmits); a failed read stops the server, and its supervisor
starts it again, with a fresh pool -- in-memory, as the leases always were.

## Testing

`go test` calls `answer` directly: a DISCOVER gets an OFFER framed to the broadcast address it asked
for, the pool given left as it was; a non-DHCP packet gets nothing; an invalid subnet fails the
tree's start before any socket opens. `pkg/dhcpv4`'s own tests cover the protocol. End to end, the
netns rig's `MM_DHCPV4=1` has a real `dhclient` lease an address from it.
