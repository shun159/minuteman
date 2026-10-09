# pkg/datapath

The **only** package that talks to `cilium/ebpf` or knows a BPF map layout. Everything else in
minuteman configures and drives the XDP datapath (`bpf/datapath.bpf.c`) through the exported
`Loader` API, in `netip.Addr`/`net.HardwareAddr` terms — never through map handles.

That boundary is the reason this package exists as one: the C side's map layouts, the `enum
stat_id` ordering, the migration control word's bit packing and the `frag_unit` derivation are
all things that must move together with the datapath, and keeping them in one package means a
change to `bpf/datapath.bpf.c` has exactly one Go counterpart to update.

## Build

`gen.go` holds the `//go:generate bpf2go` directive that is the source of truth for how the
object is compiled and embedded. `make` / `make build-bpf` runs it; regenerate by hand with
`go generate ./pkg/datapath/...` after editing the BPF C sources. The generated
`bpf_x86_bpfel.go` + `.o` are gitignored.

`Load()` calls `rlimit.RemoveMemlock()`, so callers need only root / `CAP_BPF` + `CAP_NET_ADMIN`,
not a pre-raised memlock limit.

## Files

| File | What it owns |
| --- | --- |
| `loader.go` | `Load`, `AttachWAN`, `AttachLAN`, `Close` |
| `types.go` | `B4Config`, `LANConfig`, `Stats` — the API-boundary types |
| `config.go` | `SetB4Config`, `SetLANConfig`, `SwitchAFTR`, the next-hop slot discipline |
| `migration.go` | the graceful AFTR-migration state machine + flow-affinity GC |
| `mss.go` | TCP MSS clamp policy (`TCPMSSClampAuto`, `autoTCPMSSClamp`) |
| `frag.go` | `EnableSoftwireFrag`, `MaxSoftwireFrags`, the `frag_unit` derivation |
| `pmtu.go` | `TunnelPMTU`, `SetSoftwireMTU`, `TunnelPMTUExpiry` |
| `ipv6_rss.go` | `EnableIPv6SoftwareRSS` (the optional native-IPv6 cpumap stage) |
| `stats.go` | `Stats()`, `ReadPinnedStats()`, the hand-maintained `statID` enum |
| `pin.go` | pinning the stats map and the xdpcap capture hooks to bpffs |
| `xdproles.go` | `XDPRoles` — which attached XDP program ids are this instance's, and what each does |
| `sysctl.go` | the forwarding / `accept_ra` sysctls the FIB lookups need |

## Attach, and the sysctls that come with it

`AttachWAN` attaches the decap program and **also** writes three sysctls (`sysctl.go`, plain
`/proc/sys` file writes — no `sysctl` exec, matching `pkg/netlink`'s no-library stance):

- `net.ipv4.ip_forward` and `net.ipv6.conf.all.forwarding` — both process-wide, and both
  required by *both* programs regardless of which interface they are attached to, since encap
  and decap each do FIB lookups in both families. Without them `bpf_fib_lookup()` returns
  `BPF_FIB_LKUP_RET_FWD_DISABLED` for every packet and nothing is encapsulated at all.
- `accept_ra=2` on the WAN interface — enabling forwarding otherwise suppresses RA acceptance,
  and the WAN needs its SLAAC addresses and RA-installed default route to keep being refreshed.

`accept_ra=2` is written *first*, so no RA arriving mid-sequence is dropped. That still isn't
enough on its own: the forwarding 0→1 transition makes the kernel purge every already-RA-learned
default route (`rt6_purge_dflt_routers`) regardless, leaving the WAN with no route to the AFTR
until the ISP's next unsolicited RA — minutes away. That is why `cmd/minuteman` fires
`pkg/routeradvert.SolicitRouters` immediately after `AttachWAN`. It is not a theoretical concern:
it was an end-to-end failure observed in the netns rig, where encap's FIB lookup failed for every
packet until dnsmasq's next periodic RA.

`AttachLAN` may be called once per LAN interface. Both register their ifindex in `tx_ports`
(self-mapped, `config.go`'s `registerTxPort`), which is what makes them valid
`bpf_redirect_map()` targets.

## Softwire endpoints: the next-hop slots

The datapath holds `numNextHops` = 2 endpoint slots plus a single-`__u32` control word. Two is
exactly enough for one live AFTR switch: outgoing in one slot, incoming in the other.

The slot indirection is a correctness mechanism, not bookkeeping. A `next_hop` is copied into
place on update with no RCU replacement, so **overwriting a slot the datapath is currently
resolving lets a packet in flight read a half-updated endpoint and be encapsulated to a garbage
peer**. `writeNextHop` therefore refuses to write a live slot, and `slotIsLive` — not the caller
— decides which those are. During `DRAINING` *both* slots are live, so there is simply no free
slot until the migration ends; that rule is easy to violate by accident, which is why it is
enforced in code rather than documented at call sites.

`SetB4Config` is the startup path: it validates both addresses before touching any map (a bad
address leaves the datapath untouched), fills slot 0, makes it active, and derives two things
the datapath doesn't compute for itself — `frag_unit` from `WANMTU` and `mss_clamp` from
`TCPMSSClamp`.

`SwitchAFTR` is the **hard** switch, for when in-flight flows are unrecoverable anyway (a changed
B4 address invalidates the AFTR's NAT state) or when a graceful migration must be abandoned. It
ends any migration in progress first — a correctness requirement, since otherwise there is no
free slot and "(active+1)" would overwrite the pinned flows' slot out from under them.

## Graceful AFTR migration

`migration.go` implements what `internal/softwirectl`'s controller drives: moving to a new AFTR
*without* breaking flows already established through the old one. Four calls, one control word:

```
STEADY ──BeginMigration──► PRIMING ──Cutover──► DRAINING ──CompleteMigration──► STEADY
                              │
                              └──AbortMigration──► STEADY (old AFTR)
```

- **`BeginMigration(b4, aftr)`** writes the new endpoint into the inactive slot and enters
  `PRIMING` under a fresh epoch. Traffic keeps using the old AFTR; what changes is that encap and
  decap now record every softwire flow into the affinity table. That recording is the whole
  point: after the switch, a flow-table miss cannot distinguish a brand-new flow from a
  pre-existing flow's next packet — UDP/QUIC/ICMP have no start marker — so which flows predate
  the switch must be learned *before* switching. A flow completely idle through `PRIMING` is the
  accepted, bounded cost: it is treated as new at cutover.
- **`Cutover()`** flips new flows to the new AFTR while every flow recorded during `PRIMING`
  stays pinned to the old one. Both slots remain valid, so decap accepts return traffic from
  either AFTR for the whole drain. The caller **must** check that `Stats().AffinityInsertFail`
  did not rise during `PRIMING` first: an unrecorded flow may be pre-existing and would be
  silently moved to an AFTR with no NAT state for it. That counter only rises when the table is
  genuinely full — the datapath records with `BPF_ANY`, so two CPUs racing on the same flow can't
  be mistaken for a loss.
- **`CompleteMigration()`** returns to `STEADY` on the new AFTR, then retires the old slot.
  Control first, slot second — never the reverse, or a packet in flight could resolve a slot that
  was just invalidated.
- **`AbortMigration()`** is valid from `PRIMING` only. From `DRAINING` it is deliberately
  unsupported: traffic has already moved, and going back would strand the flows that migrated.

**`GCFlowAffinity(timeouts)`** reclaims entries and returns how many current-epoch (still-pinned)
flows remain — the drain's completion signal. Past-epoch entries are always deleted; whether a
*current-epoch* entry may be expired depends on the state, and the asymmetry is the interesting
part:

- `PRIMING`: **never**. Those entries *are* the record being built; expiring one on idleness
  would silently reclassify that flow as new at cutover — the exact failure `PRIMING` prevents.
- `DRAINING`: yes, on the protocol's idle timeout. Idleness is what bounds the drain rather than
  a fixed window, because an active stream keeps refreshing the old AFTR's NAT state indefinitely
  and a fixed deadline would cut a long download or a video call mid-flight. Both directions
  refresh `last_seen` (encap by the forward key, decap by the reversed one), so a
  download-heavy flow never looks idle.
- `STEADY`: yes — nothing consults the table, so leftovers are inert clutter.

Deletion happens after the iteration, not during it: removing entries mid-walk can make a HASH
iteration skip others. `monotonicNanos()` reads the same `CLOCK_MONOTONIC` that
`bpf_ktime_get_ns()` stamps flows with, so the comparisons mean something.

## Path MTU, fragmentation and MSS — the three things userspace re-derives

`pmtu.go`'s `TunnelPMTU()` reports the smallest not-yet-aged-out softwire path MTU across the
slots (the minimum is deliberate: during a migration both slots carry traffic, and the value the
caller derives is a single datapath-wide one — taking the smaller costs a fragment on the wider
path and keeps the narrower one working). `TunnelPMTUExpiry` mirrors the C
`TUNNEL_PMTU_EXPIRY_NS`, so both sides age readings out on the same clock.

`SetSoftwireMTU(mtu)` applies a new reading to the two fields it owns — `frag_unit` and, if the
clamp is automatic, `mss_clamp`. These are the **only** fields of `b4_config` written after
startup. The datapath reads the struct field by field rather than as a snapshot, which is safe
here precisely because only these two move and they are read independently.

`clearTunnelPMTU(slot)` runs whenever a slot's endpoint pair changes, so a slot recycled by a
migration or a dynamic-B4 switch doesn't inherit the retired softwire's reading.

Why is `frag_unit` derived in Go at all, when the datapath knows its own MTU? Because the
fragmenter's two halves read `frag_unit` at different moments, and a value that changed in
between would produce an unreassemblable fragment set. Polling alone does not prevent that
race: encap snapshots the unit in the internal clone's IPv6 flow label, and every companion
program slices with that snapshot. The flow label is cleared before WAN transmission.

The same reasoning applies to the MSS clamp (`mss.go`), for a different reason: an MSS only
affects connections that haven't sent their SYN yet, so a poll interval of lag costs nothing, and
one value keeps both directions clamping alike — the decap side has no local MTU to derive one
from. `autoTCPMSSClamp` = MTU − 40 (outer IPv6) − 40 (option-free IPv4 + TCP; RFC 6691 is
explicit that options are *not* deducted). Below `minTCPMSSClamp` = 536 it disables itself rather
than push peers under RFC 1122 §4.2.2.6's floor — a softwire that narrow leaves the work to the
fragmenter. `resolveMSSClamp` records on the `Loader` whether the clamp was derived or pinned, so
`SetSoftwireMTU` knows whether a learned path MTU may move it.

`frag.go`'s `EnableSoftwireFrag(redirectIfindexes, fwdIfaces)` wires the in-XDP fragmenter to the
veth pairs `internal/fragpath` created: **attach then populate** — pair *i*'s trimming program
goes on its B end first (which also activates that pair's NAPI, so it consumes XDP frames at
all), and only then does `frag_ports[i]` point at the A end. The datapath's own guard checks that
`frag_ports` resolves, so this ordering means it never broadcasts into a pair with no consumer.
`MaxSoftwireFrags` (4) mirrors the C `MAX_SOFTWIRE_FRAGS` and is what `fragpath.NumPairs` is
defined from; a nil program slot fails fast with a message naming the list that fell out of sync.

## Stats

`Stats()` sums the `PERCPU_ARRAY` counters across CPUs into a plain struct. **The `statID` order
in `stats.go` and the field order in `types.go`'s `Stats` must be kept in sync with `enum
stat_id` by hand** — bpf2go can't export a Go enum here, because `enum stat_id` never appears as
a stored map value type in the BTF (only as inlined integer constants), so `-type stat_id` finds
nothing. New counters are appended before `STAT_MAX`.

`pin.go` pins the maps an out-of-band observer reaches minuteman through, and nothing else:
`stats` (`/sys/fs/bpf/minuteman/stats`), so counters stay readable while minuteman runs
(`minuteman stats [--json]` via `ReadPinnedStats`, or `bpftool map dump pinned ...`), and the two
xdpcap capture hooks (`xdpcap_hook`, `xdpcap_hook_cpu`), so a packet capture can be installed into
the running datapath — see the hook comment in `bpf/datapath.bpf.c` and
`docs/operability-backlog.md` §3. A stale pin from a crashed run is removed first
(unpin-then-repin, the same stance `internal/slowpath` takes on stale devices); pin failure is
fail-fast with a bpffs-mount hint, unpinning whatever it had already pinned so a failed start
never leaves a pin advertising a datapath that isn't there; `Close` unpins best-effort.

> **Running inside a netns:** `ip netns exec` creates a new mount namespace and remounts `/sys`,
> stranding the pin on a private bpffs. Enter with `nsenter --net=...` instead — the netns rig
> does exactly that. See `test/netns/README.md`'s "Reading datapath stats".

### Which interfaces is the datapath on? (`xdproles.go`)

`XDPRoles(progIDs)` answers that for an out-of-band observer, given the XDP program ids a link
dump reports (`pkg/netlink`'s `Link`): it returns an entry only for the ids belonging to the
**running** instance, labelled `wan` / `lan` / `frag`. `cmd/minuteman`'s `stats interfaces` uses it to
pair each interface with `pkg/ethtool`'s driver counters.

Membership is decided by the program **referencing the same map the pin points at**, not by its
name. A name proves nothing — an unrelated XDP program can share one, and so can a stale second
minuteman whose pin has already been replaced — whereas a map id is unique per loaded map. Every
interface-attached program bumps a stats counter, so this check misses none of them. The name is
then used only for the role label, comparing both sides truncated to `BPF_OBJ_NAME_LEN-1`: the
kernel's name field is 15 characters, and `cilium/ebpf` recovers the untruncated name from BTF
func info only when the object carries it.

## Optional: native-IPv6 software RSS

`EnableIPv6SoftwareRSS(cpus)` turns on the cpumap fanout stage for the native-IPv6 forwarding
fastpath: it populates `cpu_map_v6` with `bpfBpfCpumapVal{Qsize, prog: XdpIpv6FwdCpu.FD()}` per
CPU, fills `ipv6_rss_cpus`, and sets `ipv6_rss_config`. (`cilium/ebpf` v0.21 has no high-level
CPUMAP-with-program helper, so the raw bpf2go-generated struct is `Put` directly.)

It is **off unless called** — `-ipv6-sw-rss`. On a NIC with capable hardware RSS (mlx4 and
friends) it is redundant overhead. It deliberately uses its own maps rather than the DS-Lite
`fanout_*`/`cpu_map` set, which is dormant and never enabled from Go: IPv6 software RSS must be
switchable without waking that path.

## Testing

```sh
go test ./pkg/datapath/          # pure: control-word packing, MSS derivation
sudo go test ./pkg/datapath/     # adds migration_state_test.go (loads BPF maps)
```

`migration_test.go` pins the migration control word's bit layout against what the C side reads —
a mismatch there would silently route packets to the wrong AFTR slot, so it is asserted
explicitly rather than trusted. `migration_state_test.go` drives the real state machine against
kernel maps and skips itself when not run as root. Everything about actual packet forwarding is
exercised by the netns rig (`test/netns/README.md`).

Run the actual fragment-program snapshot regression with
`sudo env MM_BPF_TEST=1 go test ./pkg/datapath -run TestFragmentUnitSnapshot -v`.
It changes the live unit between clones and verifies offsets, payload reconstruction,
and removal of the private flow label.
