# internal/softwirectl

The single owner of the live softwire endpoints — which B4 and which AFTR the datapath, and its
companion ip6tnl, carry traffic between. `cmd/minuteman`'s `startSoftwireControl` starts it
whenever the AFTR or the B4 is dynamic:

- **dynamic AFTR** — periodic re-discovery (RFC 4242 / HB46PP ttl); a changed AFTR is applied
  through `pkg/datapath`'s flow-preserving migration, never a hard switch.
- **dynamic B4** — the kernel's chosen source toward the AFTR is polled every 30s; a change
  hard-switches the softwire (the DS-Lite B4-address change of RFC 7785) and re-discovers the
  AFTR at once, as the VNE may map the new prefix to a different one.

It is written with [molecule](https://github.com/shun159/molecule): a supervision tree of two
processes.

```
softwirectl-sup (rest_for_one)
├── softwire        genserver: the datapath, tunnel and netlink calls
└── softwirectl     genstatem: the Controller, pure; discovery runs in an Async of its own
```

## The controller

`Controller` decides everything and does nothing: its `HandleEvent` returns the next phase and
the requests to send, and the runtime sends them. So the policy is tested by calling it, or by
running the whole tree in `gensim` with a fake datapath and a fake discovery (`sim_test.go`) —
migrations, a WAN change mid-drain, a controller crash mid-drain — on a virtual clock, where a 2h
drain cap takes no time. A WAN change mid-discovery is tested by calling `HandleEvent` itself: in
gensim the discovery's Async is done before anything can come in between.

```
           refresh              new AFTR                 primed, nothing lost
Recovering ──► Steady ─────► Discovering ─────────► Priming ─────────────────► Draining
                 ▲               │ unchanged/failed    │ lost flows/failure       │ drained or capped
                 └───────────────┴─────────────────────┴──────────────────────────┘
       any phase ── WAN source changed ──► Switching ──► Steady (re-discover at once)
```

| Phase | Waiting for |
| --- | --- |
| `Recovering` | the softwire's endpoints — every start, a restart included |
| `Steady` | the refresh (state timeout) |
| `Discovering` | the discovery attempt |
| `Priming` | `BeginMigration`, the 60s priming window (state timeout), the counters, `Cutover` or `AbortMigration` |
| `Draining` | each 30s drain tick (state timeout) and its `GCFlowAffinity`; the 2h cap is a generic timeout |
| `Switching` | `SwitchAFTR`; the B4 poll is postponed meanwhile |

A hard switch can happen in any phase: `SwitchAFTR` ends a migration whatever its state, and a
discovery in flight is cancelled. Rather than tracking what each phase left half-done, a switch
bumps `Data.Gen`, the generation every request is tagged with, and every response of an earlier
one is dropped as stale. Mid-drain, it switches onto the new AFTR, where new flows already go.

## Restarts

The `Softwire` value — the endpoints carrying traffic, and whether a migration is under way — is
made by `cmd/minuteman` and outlives the processes. A restarted controller starts in
`Recovering`, asks the `softwire` server, which ends a migration left behind (`SwitchAFTR` onto
the endpoints new flows use), and goes on from there; if the AFTR moved since startup, the
refresh pacing and HB46PP token died with the old controller, so it re-discovers at once.

The supervisor is `rest_for_one`, the controller depending on the softwire server. Past its restart
intensity it gives up, and `startSoftwireControl` fails the whole of minuteman, for whatever
supervises minuteman to start it cleanly.

## Discovery

A discovery attempt blocks, for up to 2 minutes, which a callback must not: the controller runs it
as a `molecule.Async`, its outcome arriving as an `AsyncResult`, and a hard switch cancels it with
`CancelAsync` -- its ctx done, its outcome never delivered. `hb46pp.RetryDelay`'s backoff is
random, so it is drawn in the Async too, and the controller stays deterministic.
