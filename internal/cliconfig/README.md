# internal/cliconfig

Parses minuteman's command-line flag *values* into typed configuration, so
`cmd/minuteman/main.go` stays a thin wiring layer between `flag` definitions and the
`pkg/datapath` API.

This package is CLI glue only. It holds no protocol logic and no policy: what a delegated
prefix means for the LAN belongs in `internal/lanprefix`, what an MSS clamp *does* belongs in
`pkg/datapath/mss.go`, and every wire format belongs in its own `pkg/` package. What lives
here is the mapping from an operator-typed string to a value one of those packages accepts,
plus the validation that makes a typo fail at startup rather than three layers down.

## Files

| File | Flag(s) | What it produces |
| --- | --- | --- |
| `lan.go` | `-lan` | `LANSpec` / `LANSpecList` |
| `addr.go` | `-dns-server`, `-dhcpv4-dns` | `AddrList` |
| `mac.go` | `-wan-dst-mac` | `net.HardwareAddr` |
| `mssclamp.go` | `-tcp-mss-clamp` | `datapath.B4Config.TCPMSSClamp` |

`LANSpecList` and `AddrList` implement `flag.Value`, which is what makes their flags
repeatable — one `-lan` per LAN interface, one `-dns-server` per upstream.

## `-lan iface=gatewayIP[/prefixlen][,mtu]`

One flag value carries three separate consumers' worth of configuration, which is why
`LANSpec` has fields that not every run uses:

- `GatewayIP` is all the DS-Lite datapath itself needs (it becomes `lan_config.gateway_ip`).
- `Subnet` exists for `-dhcpv4`, which carves its address pool from it. An omitted prefix
  length defaults an IPv4 gateway to a `/24` (the conventional home-LAN size); an IPv6
  gateway gets no `Subnet` at all, since there is no DHCPv4 pool to derive.
- `MTU` is the inner (LAN-side) MTU, `0` meaning "use the interface's current MTU". It is
  bounded to 68..65535 — RFC 791's minimum IPv4 MTU at the bottom, and at the top the ceiling
  shared by the datapath's `uint16` `InnerMTU` and the DHCP Interface MTU option (26).

`cmd/minuteman`'s `attachLAN` applies one further bound this package deliberately does *not*:
an MTU above `fragpath.MaxInnerLen` is rejected there, because that ceiling comes from the
fragmenter's companion veth pairs rather than from anything about the flag's syntax.

## `-tcp-mss-clamp auto|off|<mss>`

`ParseMSSClamp` resolves the three spellings into the integer policy
`datapath.B4Config.TCPMSSClamp` takes: `datapath.TCPMSSClampAuto` (derive the clamp from the
softwire MTU and track a learned path MTU), `0` (no clamping — also spelled `off`/`none`), or
a pinned MSS in bytes.

An explicit MSS is range-checked to 536..65495. The floor is RFC 1122 §4.2.2.6's value every
IPv4 endpoint must accept without path MTU discovery: a smaller number is far likelier an MTU
typed where an MSS belonged than a real intent, and `off` already expresses "don't clamp". The
ceiling is a sanity bound — the field is 16 bits, but a value no Ethernet-derived MTU could
reach never clamps anything.

An empty string parses as `auto` rather than erroring, so a caller that drops the flag's
default still gets the default behavior.

## Testing

`lan_test.go` and `mssclamp_test.go` are ordinary `go test` unit tests — this package is pure
string parsing with no I/O, so unlike most of minuteman it needs neither root nor the netns
rig:

```sh
go test ./internal/cliconfig/
```
