# 7. Findings not fixed

A fresh re-check of `AUDIT.md` against the repository as it stands after this
fix — not a copy of the original list. All four Critical findings are now
closed.

## A. H1 (`d.timers` leak) is closed as a side effect of this fix

`AUDIT.md` H1 was the same defect as C3's "compounding leak" note, listed
separately under High. Re-checked directly: `d.stopSessionTimer(npmPID)` now
runs unconditionally at the top of the timeout callback (`detector.go:441`),
before the completion-arbitration check, so every session that times out
removes its own `d.timers` entry regardless of which path wins the race.
Pinned by `TestSessionTimeoutClearsItsOwnTimerEntry`, teeth-checked in
[02-tests.md](02-tests.md) slice 3.

**H1 can be marked fixed alongside C3** — it was never a separate bug, just a
separate audit line for the same root cause.

## B. `Session.Complete()` is now dead in production, but still exported and callable — new, Low

Before this fix, `Complete()` was the only way either completion path marked
a session done. After this fix, `handleExit` and the timeout callback both
call `MarkCompleteOnce` instead, and `Complete()` has no production caller —
confirmed by grep, its only remaining callers are two session-level unit
tests (`TestStateTransition`, `TestSnapshotCopiesSessionIdentity`) that just
need a session in the `Complete` state and are not exercising completion
arbitration.

**Why not fixed:** it does no harm sitting unused today, and removing it would
require updating those two tests to call `MarkCompleteOnce` instead, which is
a real behavior change to tests outside this fix's scope (goal 5: nothing
else changes).

**Why it is sharp:** `Complete()` still bypasses `sync.Once` entirely. If any
future production code called `session.Complete()` directly — instead of
`MarkCompleteOnce` — it would silently reintroduce exactly the C3 double-
completion bug this task closed, with no compiler warning. `MarkCompleteOnce`
is the *only* correct way to transition a session to `SessionComplete` from
production code, but nothing enforces that today except this document and the
comments on `MarkCompleteOnce` itself.

**Suggested shape:** either unexport `Complete()` to a test-only helper (e.g.
move the two tests to construct the desired state via `MarkCompleteOnce`
directly and delete `Complete()`), or rename it to make its narrow, non-arbitrating
purpose explicit (`completeUnguarded` or similar) so a future reader cannot
reach for it by accident.

## C. The end-to-end race is proven at a synthetic timeout width, not the production default

Slice 2's stress test uses a 1-microsecond `sessionTimeout` to force the race
on every trial. The production default is much longer (well over a second),
so the *frequency* of this race in a real capture run was never measured —
only that the race is real and that the fix closes it whenever it occurs.

**Why not fixed further:** measuring real-world frequency would require an
actual long-running capture with real npm installs, which is dataset-generation
work, not a unit-test seam. The fix itself does not depend on timeout width —
`MarkCompleteOnce`'s guarantee holds regardless of how the two goroutines are
scheduled — so this is a measurement gap, not a correctness gap.

---

## Re-checked, unchanged from the prior fix's findings

Everything below was re-read against the current repository state, not
copied forward from [`../fix-c2-buildrecord-race/07-findings-not-fixed.md`](../fix-c2-buildrecord-race/07-findings-not-fixed.md)
or `AUDIT.md` unverified. None of it is touched by this task's diff.

- **H2 — `pending_opens` BPF map leaks on SIGKILL mid-`openat`.** Unrelated
  subsystem (`bpf/file_monitor.bpf.c`); untouched by this fix.
- **H3 — `Detector.Run()`/`Submit*` is dead in production.** Re-confirmed:
  `cmd/monitor/main.go:145-146` still starts both `detector.Run(ctx)` and
  `router.Run(ctx)`, and `Router.Run` still calls `detector.HandleProcess`/
  `RouteToSession` directly rather than through any `Submit*` method. This
  fix's own detector-level tests (slice 2, slice 3, slice 4) drive the
  detector through `Submit*` + `Run`, same as the pre-existing tests H3
  already flagged — they exercise the arbitration logic correctly (which
  lives in `handleExit`/the timeout callback either way) but not the
  production `Router`→`Detector` call path itself.
- **H4 — router priority pattern doesn't guarantee cross-channel ordering.**
  Unrelated to session completion; untouched.
- **H5 — silent event drops under backpressure, uncounted.** Unrelated;
  untouched.
- **H6 — `ml_handoff.md`'s CSV column table is self-contradictory.**
  Documentation-only; untouched.
- **H7 — PID-reuse aliasing on `pidToSession`.** Unrelated to completion
  arbitration; untouched. Worth noting for context: this fix does not change
  when `unregisterSession` runs relative to PID reuse, so H7's window is
  exactly as wide as before.
- **Medium — no `-race`/`test` Makefile target, no CI.** Re-confirmed:
  `grep -n "^test" Makefile` finds nothing; the only `.PHONY` targets are
  `generate build run run-only clean help`. This fix's `-race` and root
  evidence in [06-results.md](06-results.md) was run by hand, same as C2's —
  neither would be caught by normal `make` usage.
- **Medium — `unregisterSession`'s full linear scan of `pidToSession`.**
  Re-read at `detector.go:365-375`: unchanged, still O(N) in total tracked
  PIDs on every completion. Not touched by this fix.
- **All other Medium/Low items** (dead stubs, stale script binary name,
  `Makefile clean` wrong directory, unpinned toolchain, duplicate BPF object
  loads, `InstallExtractor` error handling, loose `isNpmInstallInvocation`
  substring match, and the Low items) — re-read, none reference session
  completion or timers, none touched by this diff.

---

## Still open, in order of what this unblocks

With all four Critical findings fixed, the next-highest-value items by the
audit's own severity ordering are the High findings not yet addressed: H2
(BPF map leak), H3 (dead `Detector.Run` machinery vs. the real `Router`→
`Detector` path), H4 (cross-channel ordering), H5 (uncounted event drops), H6
(doc-only), H7 (PID-reuse aliasing). H5 and H7 compound with each other (a
dropped EXIT can enable PID-reuse aliasing) and are the two most directly
relevant to running the long, high-throughput capture this project's C2/C3
fixes were explicitly justified by.
