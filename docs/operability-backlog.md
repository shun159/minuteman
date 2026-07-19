# Operability & testability backlog

Separate from `docs/rfc-compliance-backlog.md` (which tracks protocol correctness): this file tracks
operational and test-ergonomics improvements — how minuteman is run, observed, and driven under test —
that don't change datapath behavior but make the system easier to operate and to verify. Ordered by
leverage, highest first. Last checked against the codebase 2026-07-19.

Motivation: the netns rig (`test/netns/`) currently has to run minuteman as a foreground process whose
stdout it keeps captured, then grep `-stats-interval` log lines for datapath counters. That couples every
assertion to the process's stdout and its lifetime, and it makes "send some traffic, then read a counter"
awkward — you can't query a running instance out-of-band, and detaching the process is fragile. The two
items below remove that coupling.

## 1. Query datapath stats out-of-band via a pinned BPF map + a `stats` subcommand (highest leverage)

Today the `stats` `PERCPU_ARRAY` lives only inside the running process: `pkg/datapath`'s `loadBpfObjects`
does a plain `LoadAndAssign` with no pinning, so the map vanishes when minuteman exits and nothing else can
read it. Stats are exposed only by the `-stats-interval` stdout logger (`cmd/minuteman`'s
`logStatsUntilDone`).

**Proposal:** pin `stats` (and, if useful, `migration_ctrl` / `next_hops`) to bpffs
(`/sys/fs/bpf/minuteman/…`) when the datapath loads, and add a `minuteman stats [-json]` subcommand that
opens the pinned map with `ebpf.LoadPinnedMap` and reuses `stats.go`'s cross-CPU summing to print the same
`Stats` struct. This fully decouples stats reading from minuteman's stdout: a test can send traffic and
then, in a separate short command, read the exact counters (`minuteman stats -json | jq .DecapMartian`).
`bpftool map dump pinned /sys/fs/bpf/minuteman/stats` becomes possible too.

**Notes / gotchas:**
- Pinning changes lifecycle: a pinned map persists after the process exits unless explicitly unpinned.
  Need cleanup on graceful shutdown (unpin in `Loader.Close`), plus a way to clear a stale pin from a
  previous crashed run (unpin-then-repin, mirroring `internal/slowpath`'s stale-device cleanup).
- Requires a bpffs mount (`/sys/fs/bpf`, standard on modern systems); fail with a clear message if absent.
- CLI shape: keep the current flag set as the default `run` behavior for backward compatibility and add
  `stats` as a subcommand — a small `main()` refactor (dispatch on `os.Args[1]` before `flag.Parse`).
- `stats.go`'s `Stats()` is currently a `*Loader` method; factor the summing so it can also run against a
  bare pinned-map handle (the subcommand has no full `Loader`).

**Testing payoff:** the `MM_SOFTWIRE_FRAG` smoketest's counter assertions (`EncapFragSlow`,
`DecapReasmPass`, `DecapMartian`) could read the pinned map directly instead of grepping stats log lines,
and would no longer need minuteman started with `-stats-interval` and its stdout owned by the script.

## 2. Daemon / detach mode so the process survives its launcher

minuteman runs in the foreground; the rig backgrounds it with `&` and keeps its stdout. That is fragile —
a launcher that tears down its process group takes minuteman with it (this bit hard when trying to run
minuteman concurrently with packet senders under an automated harness: the backgrounded process was killed
and its output lost).

**Proposal:** for production, lean on the init system rather than self-daemonizing — a systemd unit
(`Type=simple`, or `Type=notify` with `sd_notify` readiness) manages the lifetime cleanly, and Go's lack of
a clean `daemon(3)` primitive makes self-daemonizing (re-exec + double-fork + setsid + fd close) the worse
option. Ship an example unit under `test/netns/` or `docs/`. For the test rig specifically, running
minuteman under `systemd-run --scope` (or a properly detached session) would let it outlive the launching
command, so senders and `minuteman stats` can run against it in separate steps.

**Notes:**
- Signal handling already exists (`signal.NotifyContext` on SIGINT/SIGTERM), so graceful shutdown under a
  service manager needs no new plumbing beyond optional `sd_notify`.
- A `-pidfile` option (write pid, remove on exit) helps a supervisor and the rig track the instance.
- Lower priority than #1: #1 alone removes most of the test friction (stats no longer need the process's
  stdout), and production deployment is a packaging concern a systemd unit covers without code changes.
