# Operability & testability backlog

Separate from `docs/rfc-compliance-backlog.md` (which tracks protocol correctness): this file tracks
operational and test-ergonomics improvements — how minuteman is run, observed, and driven under test —
that don't change datapath behavior but make the system easier to operate and to verify. Ordered by
leverage, highest first. Last checked against the codebase 2026-07-19.

## 1. Query datapath stats out-of-band via a pinned BPF map + a `stats` subcommand — **DONE**

Implemented: `pkg/datapath.Load` pins the `stats` `PERCPU_ARRAY` to bpffs
(`/sys/fs/bpf/minuteman/stats`), replacing any stale pin a previous crashed run left behind
(unpin-then-repin, mirroring `internal/slowpath`'s stale-device cleanup) and failing fast with a
bpffs-mount hint if pinning is impossible; `Loader.Close` unpins best-effort on graceful shutdown. The
`minuteman stats [-json]` subcommand (dispatch on `os.Args[1]` before `flag.Parse`, so the flag-only
invocation stays the default run behavior) reads it via `datapath.ReadPinnedStats`
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
all-pass with the delta assertions; manual `stats`/`stats -json`/`bpftool map dump` against a live
instance; counters advance with traffic; kill -9 → restart replaces the stale pin with fresh zeroed
counters; SIGTERM removes the pin.

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
