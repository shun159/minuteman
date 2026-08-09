# pkg/ethtool

A minimal, hand-rolled `SIOCETHTOOL` client that reads one thing: a network device's
driver-specific statistics — the counters `ethtool -S <interface>` prints.

It exists so `minuteman stats -iface` can show, in the same output as the datapath's own counters,
what the drivers underneath the XDP programs see: a veth's `rx_queue_N_xdp_packets` /
`xdp_redirect` / `xdp_drops`, a real NIC's per-queue and per-XDP-action counters. Those are the
numbers that distinguish "the datapath didn't handle it" from "the packet never arrived", and
having them beside the datapath counters removes a manual correlation step between two tools.

No `ethtool` exec and no ethtool library — the same no-sidecar stance as `pkg/netlink`
(hand-rolled rtnetlink) and `pkg/datapath/sysctl.go` (writes `/proc/sys` rather than exec'ing
`sysctl`).

## API

```go
stats, err := ethtool.Stats("eth0")   // []Stat{Name, Value}, driver order preserved
```

`ErrNotSupported` means the driver exposes no `ETH_SS_STATS` counters at all — loopback, most
virtual devices other than veth, and drivers predating these ioctls. It's a distinct sentinel so a
caller can report "nothing to show" for one interface without failing over the others.

Order is preserved as the driver reports it, which is the order `ethtool -S` prints: drivers group
related counters (per queue, per XDP action), and alphabetising scatters those groups. That's why
`Stats` returns a slice and not a map — `cmd/minuteman` builds the map itself, for JSON output only.

## How it works

Three ioctls, the same sequence `ethtool(8)` itself uses:

| Command | Struct | Reads |
| --- | --- | --- |
| `ETHTOOL_GSSET_INFO` | `ethtool_sset_info` | how many `ETH_SS_STATS` counters exist |
| `ETHTOOL_GSTRINGS` | `ethtool_gstrings` | their names, as fixed 32-byte NUL-padded fields |
| `ETHTOOL_GSTATS` | `ethtool_stats` | their `__u64` values |

They aren't atomic with respect to each other, but the name list only changes when the driver is
reconfigured (a queue-count change), so a torn read is a vanishing case that would at worst
mislabel.

Three details that are easy to get wrong:

- **Buffer alignment.** `struct ethtool_stats`' trailing `__u64` array needs 8-byte alignment, which
  `make([]byte, n)` does not promise. `alignedBuf` allocates `[]uint64` and views it as bytes, so the
  alignment comes from the element type.
- **`ifreqData` must be the *whole* `struct ifreq` wide**, not just the name plus the `ifr_data`
  pointer SIOCETHTOOL reads. The kernel's socket-ioctl path copies a full `struct ifreq` in from user
  space before dispatching on the command, so a short object gets read past — an `EFAULT` when it
  lands at the end of a mapping, and otherwise a silent read of whatever Go put next to it. The
  trailing pad is *derived* (`unsafe.Sizeof(unix.Ifreq{}) - IFNAMSIZ - SizeofPtr`, a compile-time
  constant off `x/sys/unix`'s per-architecture generated layout) rather than written out, because the
  union's width comes from `struct ifmap`'s `unsigned long`s and so is arch-dependent: 40 bytes total
  on 64-bit, 32 on 32-bit. A compile-time assertion catches the narrow case.
- **"Unsupported" is not always an error.** The kernel *clears* `sset_mask`'s bit for a string set the
  driver doesn't implement, returning success with an empty result; older drivers return `EOPNOTSUPP`
  or `EINVAL` instead. All three become `ErrNotSupported`.

Constants `golang.org/x/sys/unix` doesn't export (`ETH_SS_STATS`, `ETH_GSTRING_LEN`) and the
`ifreq` layout `SIOCETHTOOL` uses are vendored locally, the same way `pkg/netlink` vendors
`IFLA_IPTUN_*` and `pkg/routeradvert` vendors `ICMP6_FILTER`.

## Why not the ethtool netlink interface?

Because it cannot serve these counters. The newer ethtool **netlink** interface
([`ethtool-netlink`](https://docs.kernel.org/networking/ethtool-netlink.html)) says so about its own
`ETHTOOL_MSG_STATS_GET`:

> Get standard statistics for the interface. Note that this is **not a re-implementation of
> `ETHTOOL_GSTATS`** which exposed driver-defined stats.

What it returns is the standardised groups — `eth-phy`, `eth-mac`, `eth-ctrl`, `rmon`, `phy`. The
driver-defined set `-S` prints, which is where every `xdp_packets` / `xdp_redirect` / `xdp_drops`
counter lives, has no netlink equivalent; `ethtool -S` itself still issues the ioctls above for it.
`ETHTOOL_MSG_STRSET_GET` does serve `ETH_SS_STATS` *names* over netlink, but with the values
ioctl-only that would only split one report across two transports.

The standardised groups would be an **addition**, not a replacement, if a use appears: they'd need a
generic-netlink client (family resolution via `CTRL_CMD_GETFAMILY`, nested attributes), which
`pkg/netlink` — `NETLINK_ROUTE` only — doesn't have today, and a veth exposes none of them, so the
netns rig couldn't exercise the result.

## Testing

Nothing here is unit-tested: every function is a syscall wrapper, so — like `pkg/ndproxy`'s and
`pkg/routeradvert`'s raw-socket I/O — it is exercised by the netns rig instead of by `go test`.
