# internal/fragpath

Owns the companion veth pairs the XDP datapath's softwire (outer IPv6) fragmenter bounces its
clones through — RFC 6333 §5.3's outbound half, done in XDP rather than punted to the kernel.

## Why the clones need somewhere to bounce

XDP emits exactly one frame per input frame, so fragments have to be made by *cloning*.
`encap_fragment_outer` (`bpf/datapath.bpf.c`) encapsulates the oversized inner IPv4 once behind
outer Ethernet + IPv6 (`nexthdr = IPPROTO_FRAGMENT`) + a Fragment header, then
`bpf_redirect_map`s the whole untrimmed frame into the `frag_ports` `DEVMAP` with
`BPF_F_BROADCAST` — one clone per possible fragment. An XDP program on the receiving side trims
each clone down to fragment *i* and redirects it out the real WAN.

Two kernel constraints, both found empirically, decide where those clones can go:

1. **The devmap enqueue validates the untrimmed clone's length against the target device's MTU
   before any program could trim it** (`is_valid_dst` → `xdp_ok_fwd_dev`). A frame that needs
   fragmenting by definition exceeds the WAN MTU, so the targets must be large-MTU devices —
   never the WAN itself.
2. **Enqueued frames are batched per target *device*, and only the batch's first devmap egress
   program runs over all of them.** So per-entry `bpf_devmap_val` programs on one shared device
   cannot express per-fragment behavior. Trying it produced four identical fragment-0s.

Hence **one veth pair per fragment index**, which is what this package creates.

## The devices

| Name | Role |
| --- | --- |
| `mm-frag<i>` | the A end; `frag_ports[i]` broadcasts into it |
| `mm-frag<i>p` | its peer, running `xdp_softwire_frag<i>` as its rx program (attached by `pkg/datapath`) |

`NumPairs` = `datapath.MaxSoftwireFrags` (4), mirroring the C `MAX_SOFTWIRE_FRAGS`.

Attaching the trimming program to the B end is also what activates the pair's NAPI, so it
consumes XDP frames at all — which is why `pkg/datapath.EnableSoftwireFrag` attaches first and
populates `frag_ports` second. The datapath's own guard checks that `frag_ports` resolves, so it
never broadcasts into a pair with no consumer.

`vethMTU` is **3456**: as large as a veth with single-buffer XDP attached allows, since the
attach requires MTU + headroom + `skb_shared_info` to fit one page (`ERANGE` beyond ~3.5KB on
4K pages). The fragments leaving the pairs are WAN-MTU-sized regardless — the MTU only bounds
the oversized clones admitted *into* a pair.

`MaxInnerLen` = `vethMTU - 48` is that admission ceiling expressed as an inner IPv4 length: the
enqueue admits a clone only when its frame (inner + 14-byte Ethernet + 40-byte outer IPv6 +
8-byte Fragment header) fits `vethMTU` plus the Ethernet header — the 14 cancels, leaving 40 +
8. It is handed to the datapath as `b4_config.frag_max_inner` so anything larger falls back
to the `internal/slowpath` ip6tnl (`STAT_ENCAP_FRAG_SLOW`) instead of blackholing into a
rejected broadcast. `cmd/minuteman`'s `attachLAN` also rejects a `-lan` MTU above it.

IPv6 is disabled per device via sysctl so the kernel doesn't chatter DAD/MLD into pairs that
carry nothing but datapath frames. Best-effort — stray kernel packets are dropped by the
trimming programs anyway — and the pairs get no IP address.

## Lifecycle

Same shape as `internal/slowpath`: one long-lived netlink socket opened by `New()`, devices
created by `Ensure()`, best-effort teardown in `Close()`. Single-writer, so unlike
`slowpath.Tunnel` it needs no lock — `cmd/minuteman` drives it from startup only.

`Ensure()` deletes whatever a previous crashed run left behind (both ends, since an operator
could have renamed one out from under its peer) before creating each pair, then brings both
ends up. **Fail-fast**: without the pairs the fragmenter has nowhere to send its clones, and
`cmd/minuteman` only enables it — by setting `b4_config.frag_unit` in `SetB4Config` — after
this succeeds.

Unlike `slowpath.Tunnel`, these devices are **endpoint-independent**: the fragments carry
whatever softwire addresses the encap program already wrote, so nothing here needs repointing
on an AFTR migration or a B4 switch.

`RedirectIfindexes()` returns the A ends in fragment order (what `frag_ports` points at);
`FwdNames()` returns the B ends (where the trimming programs attach). Both feed
`pkg/datapath.EnableSoftwireFrag`.

One ordering note carried in `cmd/minuteman`: `Close()` is deferred such that it deletes the
`mm-frag*` devices while `dp.Close()` still holds the `xdp_softwire_frag*` links attached to
them. That is the reverse of detach-then-delete, and benign — Linux auto-detaches an XDP
`bpf_link` on `NETDEV_UNREGISTER`, and a packet arriving in that window just falls back and is
dropped by the kernel — but it is called out explicitly there rather than left implicit.

## Testing

No `go test`: netlink device management only. Exercised end-to-end by the netns rig with
`MM_SOFTWIRE_FRAG=1`, which sends oversized **non-DF and DF** pings outbound and expects both
to round-trip through the in-XDP fragmenter (RFC 6333 errata 5847 → RFC 2473 §7.2(b) ignores
the DF bit): it asserts `EncapFragSeg` moved by two fragments per packet while `EncapFragSlow`
did not move at all, then deliberately trips a guard the other way — shrinking the WAN MTU at
runtime below the `frag_unit` computed at startup — and asserts the `EncapFragSlow` fallback
took over *and* that a DF packet on it still draws ICMPv4 Fragmentation-Needed rather than
blackholing. (The `MaxInnerLen` guard itself isn't reachable from the rig's LAN: the CPE's
XDP-attached LAN veth caps the client's MTU, so it IP-fragments before it can emit an inner
packet that large.)
`MM_TUNNEL_ICMP=1` additionally asserts `EncapFragXDP` after the fragment size is re-derived
from a learned path MTU. See `test/netns/README.md`.
