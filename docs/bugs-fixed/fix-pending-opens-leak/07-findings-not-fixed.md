# 7. Findings not fixed

A fresh re-check of `AUDIT.md` against the repository as it stands after this
fix — not a copy of the original list.

## A. The D-state (uninterruptible block) leak scenario remains unreproduced — new, honestly scoped

[02-tests.md](02-tests.md) and [05-why-this-approach.md](05-why-this-approach.md)
cover this in full: the audit's literal scenario (SIGKILL during an
interruptible `openat()`) turned out to already self-heal via the
pre-existing `sys_exit_openat` path on this kernel. The new
`sched_process_exit` hook is proven independently sufficient for that same
scenario by isolation testing, and the underlying leak is proven reachable in
principle (disabling both paths reproduces it) — but the hook's value as a
fix rests on a genuinely uninterruptible block (a thread stuck in D-state on
an unresponsive filesystem, which `SIGKILL` cannot wake), which this test
environment has no portable way to construct.

**Why not fixed further:** reproducing a real D-state block requires an
unresponsive backing filesystem — a custom FUSE server that never answers a
request, or an actually-hung network mount — either of which adds a new
system dependency and/or real-world flakiness this project's test suite does
not currently carry anywhere else.

**If it ever needs closing:** a minimal FUSE server (`libfuse`, or a Go FUSE
library) that accepts a mount but never responds to `open` would let a test
construct a thread that is provably uninterruptible, at the cost of a new
test-only dependency. Worth it only if this class of bug is independently
suspected to be biting in a real long-running capture.

## B. H5 — silent event drops under channel backpressure — still fully open, and distinct from this fix

`AUDIT.md` H5: all five collectors' `Run()` loops use `select { case
c.Events <- evt: default: /* drop */ }` with no counter or log line. Re-read
directly: `file_collector.go`'s `Run()` (and the other four collectors')
still has exactly this pattern, unchanged by this fix.

**This fix's counter is a different mechanism and does not cover H5.**
`PendingOpensInsertFailures` counts a *kernel-side* BPF map insert failing
(the map is full); H5 is about *userspace* Go channel sends being dropped
when `cmd/monitor`'s consumer is lagging behind the producer. A capture could
have zero `pending_opens` insert failures and still silently lose events to
H5's channel backpressure, or vice versa. Both are real, independent gaps;
only the first is closed here.

**Why not fixed:** out of scope for this task per `CLAUDE.md` ("fix ONLY the
vulnerability specified... do not fix... other unfixed AUDIT.md items in this
session, even if related or tempting"). H5 affects all five collectors
uniformly and deserves its own task rather than a partial fix bundled into
this one.

## C. `runDryRun`'s FileMonitor status string was stale before this fix — fixed as a direct consequence, not a drive-by

Not a new finding so much as a note for the record: the string was
hardcoded and had drifted out of sync with what `NewFileCollector` actually
attaches (missing `sys_enter_execve`... no — missing the third tracepoint,
`sched_process_exit`, which this very fix added). Corrected as part of this
change since it directly documents this fix's own attach calls — not a
sweep of other stale strings elsewhere.

---

## Re-checked, unchanged from prior work

- **H3 — `Detector.Run()`/`Submit*` dead in production.** Re-confirmed:
  `cmd/monitor/main.go` still starts both `detector.Run(ctx)` and
  `router.Run(ctx)`, with `Router.Run` still calling `detector.HandleProcess`/
  `RouteToSession` directly. Untouched by this fix.
- **H4 — router priority pattern doesn't guarantee cross-channel ordering.**
  Unrelated to file-open tracking; untouched.
- **H6 — `ml_handoff.md`'s CSV column table is self-contradictory.**
  Documentation-only; untouched.
- **H7 — PID-reuse aliasing on `pidToSession`.** Unrelated to
  `pending_opens`; untouched. Worth noting for context: `pending_opens` is
  keyed by `pid_tgid`, not the (reusable) tgid alone that `pidToSession`
  uses, and this fix's new cleanup hook fires per-thread-exit rather than
  per-tgid — it neither worsens nor improves H7's aliasing window.
- **Medium — no `-race`/`test` Makefile target, no CI.** Re-confirmed
  unchanged; this fix's `-race` and root evidence in
  [06-results.md](06-results.md) was run by hand, same as every prior fix in
  this series.
- **Medium — `TcpCollector`/`BytesCollector` double-load the same BPF
  object; `unregisterSession`'s linear scan; stale toolchain pins;** and all
  other Medium/Low items — re-read, none reference `pending_opens`,
  `file_monitor_stats`, or the new tracepoint; none touched by this diff.

---

## Still open, in order of what this unblocks

With H1 and H2 now addressed, the highest-value remaining items are H3–H7.
H5 (uncounted channel drops, all five collectors) and H7 (PID-reuse aliasing)
are the two most directly relevant to a long, high-throughput capture run —
the same theme C2, C3, and this fix have each chipped away at from a
different angle. H3's dead `Detector.Run`/`Submit*` machinery is worth
resolving before either, since it currently means a meaningful fraction of
`internal/session`'s test coverage (including some of this project's own
concurrency tests) exercises a code path production never runs.
