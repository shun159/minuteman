# Operability & testability backlog

Separate from `docs/rfc-compliance-backlog.md` (which tracks protocol correctness): this file tracks
operational and test-ergonomics improvements — how minuteman is run, observed, and driven under test —
that don't change datapath behavior but make the system easier to operate and to verify. Ordered by
leverage, highest first. Last checked against the codebase 2026-08-09.

## 1. Query datapath stats out-of-band via a pinned BPF map + a `stats` subcommand — **DONE**

Implemented: `pkg/datapath.Load` pins the `stats` `PERCPU_ARRAY` to bpffs
(`/sys/fs/bpf/minuteman/stats`), replacing any stale pin a previous crashed run left behind
(unpin-then-repin, mirroring `internal/slowpath`'s stale-device cleanup) and failing fast with a
bpffs-mount hint if pinning is impossible; `Loader.Close` unpins best-effort on graceful shutdown. The
`minuteman stats [--json]` subcommand (a cobra command tree `main` dispatches to when the first
argument isn't a flag, before `flag.Parse`, so the flag-only invocation stays the default run
behavior) reads it via `datapath.ReadPinnedStats`
(`ebpf.LoadPinnedMap` + the same cross-CPU summing `Loader.Stats` uses, factored into `sumStats`).
`bpftool map dump pinned /sys/fs/bpf/minuteman/stats` works too. Only `stats` is pinned;
`migration_ctrl`/`next_hops` can follow the same pattern if a need appears.

The netns rig's counter assertions (`MM_SOFTWIRE_FRAG`'s `EncapFragSlow`/`DecapReasmPass`/
`DecapMartian`, `MM_DUALSTACK`'s `IPv6Fwd`/`IPv6RSSRedirect`) now read the subcommand as
before/after deltas (`smoketest.sh`'s `read_stat`) instead of grepping `-stats-interval` log lines —
minuteman's stdout is no longer load-bearing for any assertion. Note the rig launches minuteman via
`nsenter --net` rather than `ip netns exec` for exactly this feature: `ip netns exec` creates a new
mount namespace and remounts `/sys`, which would strand the pin on a bpffs no later process can see
(see `test/netns/README.md`'s "Reading datapath stats").

Verified end-to-end 2026-07-19: `MM_SOFTWIRE_FRAG=1` and `MM_DUALSTACK=1 MM_IPV6_SW_RSS=1` smoketests
all-pass with the delta assertions; manual `stats`/`stats --json`/`bpftool map dump` against a live
instance; counters advance with traffic; kill -9 → restart replaces the stale pin with fresh zeroed
counters; SIGTERM removes the pin.

## 1a. Per-interface driver counters in the `stats` subcommand — **DONE**

A follow-on to #1: the datapath counters say what the XDP programs did, but not what the drivers
underneath them saw, which is exactly the difference between "the datapath didn't handle it" and
"the packet never arrived". `minuteman stats interfaces` now reports each XDP-bound interface's
`ethtool -S` counters, read through `pkg/ethtool` (a hand-rolled `SIOCETHTOOL` client:
`ETHTOOL_GSSET_INFO`/`GSTRINGS`/`GSTATS`, no `ethtool` exec, no library).

The interface list is derived from the kernel rather than from the daemon or from `-wan`/`-lan`:
`pkg/netlink.Socket.Links` (`RTM_GETLINK`) reports each device's attached XDP program id, and
`datapath.XDPRoles` keeps the ids belonging to the running instance — identified by the program
referencing the *same map the bpffs pin points at*, since a program name isn't unique but a map id
is. So the list can't drift from what's actually attached, and it covers the fragmenter's companion
veths that no flag names. It is a subcommand of `stats` rather than a flag on it, so each view keeps
a JSON shape a consumer can walk directly: `stats --json` is the `Stats` struct itself
(`jq .DecapMartian`), `stats interfaces --json` the per-interface array
(`jq '.[0].Stats.xdp_packets'`). `--json` is declared once, on `stats`, and inherited.

Verified end-to-end 2026-08-09 against the `MM_SOFTWIRE_FRAG=1` rig: roles reported correctly
(`wan` on the WAN veth, `lan` on the LAN veth, `frag` on all four `mm-frag<i>p`), and the counters
line up with the datapath's own — two oversized pings gave `EncapFragXDP: 2` / `EncapFragSeg: 4`
alongside `xdp_redirect: 2` on `mm-frag0p`/`mm-frag1p` and `xdp_drops: 2` on the two companion
pairs those packets didn't need.

Left for whoever wants it: `stats interfaces` must run in the datapath's netns to see the interfaces
(the pin itself is on the host bpffs), and there's no `--watch`/delta mode — callers diff two runs,
as `smoketest.sh` already does for the datapath counters.

## 2. Daemon / detach mode so the process survives its launcher — **PARTIAL** (unit example + `-pidfile`)

Done, per the original proposal's lean-on-the-init-system stance (self-daemonizing in Go — re-exec +
double-fork + setsid — remains deliberately rejected):
- `docs/minuteman.service.example` — a `Type=simple` systemd unit (root, `network-online.target`,
  `Restart=on-failure`) with a representative `ExecStart`.
- `-pidfile <path>` — written only after every fail-fast startup step succeeds (so its existence means
  "up", not "starting") and removed on graceful exit. Verified alongside #1 above.

Still open, in priority order:
- `sd_notify` readiness (`Type=notify`), so a supervisor can distinguish "AFTR discovered, datapath
  attached" from "still discovering". Small: write `READY=1` to `$NOTIFY_SOCKET` at the same point
  `-pidfile` is written.
- The rig still backgrounds smoketest-launched minuteman with `&` under its own process group; running
  it under `systemd-run --scope` (or a detached session) would let an instance outlive its launcher for
  multi-step manual workflows. #1 removed most of the practical pain (stats no longer need the
  process's stdout), so this is low priority.
