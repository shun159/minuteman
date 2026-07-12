
# Minuteman

Minuteman is an XDP/eBPF-based DS-Lite CPE gateway for Linux.

## Features

* DS-Lite B4 datapath using XDP
* AFTR discovery using DHCPv6 or HB46PP
* DHCPv6 Prefix Delegation
* Neighbor Discovery Proxy
* Optional DNS proxy
* Optional DHCPv4 server
* Multiple LAN interfaces

## Requirements

* Linux with BTF support (`/sys/kernel/btf/vmlinux`)
* XDP-capable network interfaces
* Go
* `clang`
* `bpftool`
* Root or equivalent BPF and network capabilities

## Build

```sh
make
```

The binary is created at:

```text
bin/minuteman
```

## Usage

```sh
sudo bin/minuteman \
    -wan <interface> \
    -b4 <IPv6 address> \
    -lan <interface>=<IPv4 gateway>[/prefix][,mtu] \
    [options]
```

### Options

| Option                       | Description                                                                                                                           |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `-wan <interface>`           | WAN interface. Required.                                                                                                              |
| `-b4 <IPv6 address>`         | B4 IPv6 address used as the local DS-Lite tunnel endpoint. Required.                                                                  |
| `-lan <spec>`                | LAN interface in `interface=gateway[/prefix][,mtu]` format. Repeatable and required at least once. The IPv4 prefix defaults to `/24`. |
| `-aftr <IPv6 address>`       | AFTR address. When omitted, Minuteman discovers it using DHCPv6 or HB46PP.                                                            |
| `-wan-dst-mac <MAC>`         | Fallback WAN next-hop MAC address when FIB lookup cannot resolve the neighbor.                                                        |
| `-stats-interval <duration>` | Datapath statistics logging interval. The default is `10s`; `0` disables logging.                                                     |
| `-dhcpv6-pd`                 | Request a delegated IPv6 prefix and assign one `/64` to each LAN.                                                                     |
| `-ndproxy`                   | Extend the WAN SLAAC prefix to the LAN using Neighbor Discovery Proxy. Mutually exclusive with `-dhcpv6-pd`.                          |
| `-dns-proxy`                 | Run a DNS proxy on each LAN gateway and forward requests over native IPv6.                                                            |
| `-dns-server <address>`      | Upstream DNS server for `-dns-proxy`. Repeatable. DHCPv6-learned servers are used when omitted.                                       |
| `-dhcpv4`                    | Run a DHCPv4 server on each LAN interface.                                                                                            |
| `-dhcpv4-lease <duration>`   | DHCPv4 lease duration. The default is `12h`.                                                                                          |
| `-dhcpv4-dns <IPv4 address>` | DNS server advertised to DHCPv4 clients. Repeatable.                                                                                  |
| `-hb46pp-vendor-id <value>`  | HB46PP `vendorid` parameter.                                                                                                          |
| `-hb46pp-product <value>`    | HB46PP `product` parameter.                                                                                                           |
| `-hb46pp-version <value>`    | HB46PP `version` parameter.                                                                                                           |

The complete option list is also available from:

```sh
bin/minuteman -h
```

## Examples

DS-Lite with DHCPv6 Prefix Delegation:

```sh
sudo bin/minuteman \
    -wan eth0 \
    -b4 2001:db8:1::2 \
    -lan eth1=192.168.1.1/24 \
    -dhcpv6-pd
```

Use Neighbor Discovery Proxy when the ISP does not delegate a prefix:

```sh
sudo bin/minuteman \
    -wan eth0 \
    -b4 2001:db8:1::2 \
    -lan eth1=192.168.1.1/24 \
    -ndproxy
```

Specify the AFTR explicitly:

```sh
sudo bin/minuteman \
    -wan eth0 \
    -b4 2001:db8:1::2 \
    -aftr 2001:db8:2::1 \
    -lan eth1=192.168.1.1/24
```

Run DHCPv4 and the DNS proxy:

```sh
sudo bin/minuteman \
    -wan eth0 \
    -b4 2001:db8:1::2 \
    -lan eth1=192.168.1.1/24 \
    -dhcpv6-pd \
    -dns-proxy \
    -dhcpv4
```

## Testing

Run the unit tests:

```sh
go test ./...
```

Run the network namespace integration test:

```sh
sudo ./test/netns/setup.sh
sudo ./test/netns/smoketest.sh
sudo ./test/netns/teardown.sh
```
