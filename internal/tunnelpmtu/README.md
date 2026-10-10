# internal/tunnelpmtu

Applies the softwire path MTU the datapath learns, as a
[molecule](https://github.com/shun159/molecule) process. When an ICMPv6 Packet Too Big about
one of minuteman's own tunnel packets arrives, the datapath records the narrower path MTU
(`handle_tunnel_icmpv6`, RFC 2473 §8), and encap clamps against it per packet at once. Two
things userspace owns follow it here: the in-XDP fragmenter's per-fragment payload size
(`datapath.SetSoftwireMTU`) and the companion ip6tnl's MTU (`slowpath.Tunnel.SetSoftwireMTU`),
which governs the fallback paths' inner-IPv4 fragmentation.

```
tunnelpmtu (one_for_one)
└── tunnel pmtu   genserver: polls the datapath, applies the path MTU
```

## Why here, and why polled

The fragment size is derived in userspace rather than in the datapath on purpose:
`encap_fragment_outer` and the `xdp_softwire_frag<i>` programs read `frag_unit` at different
moments for the same packet, so a value that changed in between would yield a fragment set that
can never reassemble. The encap stage snapshots the configured unit into each clone.

`PollInterval` is 2s. The datapath needs no poll; this only paces the two userspace-owned
values, and a couple of seconds' lag costs a handful of packets the ip6tnl fallback carries
instead of the fragmenter — the designed degradation, not a failure. The widening direction
needs no packet either: `TunnelPMTU` stops reporting an aged-out reading, and both go back to
the WAN MTU.

## The process

A genserver, impure: each tick is a BPF map lookup and, when the path MTU changed, a map update
and a netlink request, done as it is handled. What to apply is `effective`'s, pure. The two
targets are tracked apart, so a failure on one is logged and retried on the next tick without
re-applying the other. A (re)started process knows neither — its last incarnation's writes are
lost with it — so its first tick applies the effective MTU to both; a reading is logged once it
has taken, and only when it differs from the last one logged, starting from the WAN MTU.

`cmd/minuteman` starts it, as the `tunnel PMTU` application, on every run: a narrower link along
the B4–AFTR path is not a configuration. It stops before the datapath and the tunnel close.

## Testing

`go test` drives the callbacks with a fake datapath and tunnel: the WAN MTU applied quietly on
the first tick, then nothing; a narrower reading applied and logged once, its ageing out widening
both back; a wider one ignored; one target failing retried alone. End to end, the netns rig's
`MM_TUNNEL_ICMP=1` narrows the path and checks the fragment size, the ip6tnl and the MSS clamp
follow (see `test/netns/README.md`).
