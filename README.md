# Minuteman

A high-performance CPE gateway

## Testing

### Unit tests

```sh
go test ./...
```

### DS-Lite netns integration rig

`test/netns/` builds a 5-namespace RFC 6333 topology (`mm-host` LAN client → `mm-cpe` running minuteman as
the B4 → `mm-isp` IPv6 access network → `mm-aftr` AFTR simulator → `mm-inet` simulated public IPv4 internet)
to exercise the DS-Lite datapath end-to-end without physical hardware. Requires root, `dnsmasq`, and a
kernel with the `ip6_tunnel` module available (used for the AFTR's IPv4-in-IPv6 decap step). Build
`bin/minuteman` first with `make` from the repo root.

```sh
sudo ./test/netns/setup.sh       # create the namespaces/veths/routing/NAT
sudo ./test/netns/run-cpe.sh     # run bin/minuteman as the B4 inside mm-cpe
sudo ./test/netns/smoketest.sh   # start minuteman itself and verify LAN -> AFTR -> internet connectivity
sudo ./test/netns/teardown.sh    # tear everything down (safe to re-run any time, even after a partial setup)
```

`run-cpe.sh` and `smoketest.sh` omit `-aftr` by default, so minuteman discovers the AFTR live via a real
DHCPv6 exchange (RFC 3736 Information-Request + RFC 6334 `OPTION_AFTR_NAME`) against the rig's `mm-isp`
dnsmasq server. Pass `-aftr <addr>` as an extra argument to either script to override with a static address
instead. `test/netns/common.sh` holds every namespace/interface/address name used by the rig in one place.
