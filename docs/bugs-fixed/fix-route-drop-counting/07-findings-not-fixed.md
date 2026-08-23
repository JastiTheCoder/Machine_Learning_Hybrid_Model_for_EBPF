# 7. Findings not fixed

A fresh re-check of `AUDIT.md` against the repository as it stands after this
fix — not a copy of the original list.

## A. The underlying cross-channel ordering race is not eliminated — by design, stated up front

This fix makes the drop visible; it does not close the window that causes
it. [01-goals.md](01-goals.md) and [05-why-this-approach.md](05-why-this-approach.md)
cover the reasoning: eliminating it needs either a retry/replay buffer keyed
per-PID or a timestamp-based reorder buffer across all five event streams,
both real architectural additions the audit's own wording doesn't demand and
no prior fix in this series has attempted at that scale.

**If it ever needs closing:** the retry-buffer sketch in
[05-why-this-approach.md](05-why-this-approach.md) — a bounded, per-PID
pending-event queue, replayed on session registration and expired-and-counted
after a short grace period — is the smaller of the two options and would
reuse `RouteToSession`'s existing `func(*Session)` closure parameter as the
thing to hold and replay. Worth it only if the drop count observed in a real
long-running capture (now visible via `DroppedRoutesForUnknownPID` and the
shutdown log line this fix adds) turns out to be materially nonzero.

## B. `handleFork` has a structurally identical silent drop — new observation, not fixed

`handleFork` (`detector.go`): `session := d.sessionForPID(event.Ppid); if
session == nil { return }` — a FORK event for a child of a PID whose session
isn't yet known is silently dropped, with no counter and no log, for exactly
the same reason `RouteToSession`'s drop existed: an ordering race between
independent event streams (here, between a parent's own registration and a
grandchild's FORK event arriving first).

**Why not fixed:** H4's audited text names `RouteToSession` and the
syscall/file/TCP path specifically; `handleFork`'s drop, while the same
shape, is a different code path the audit doesn't cite, and extending this
fix to cover it was judged outside this task's literal scope per `CLAUDE.md`
("fix ONLY the vulnerability specified... do not fix... other unfixed
AUDIT.md items in this session, even if related or tempting").

**If it ever needs closing:** the same `routeDropCount`-and-`logf` pattern
applies directly — a `handleForkDropCount` (or a shared, event-type-tagged
counter) at the same drop site, same accessor shape.

## C. No test exercises `cmd/monitor`'s shutdown log line directly

`detector.DroppedRoutesForUnknownPID()`'s call site inside `main()` is not
covered by an automated test — consistent with how the sibling
`pending_opens`-insert-failure log line (H2) and the `LOST N of M
session(s)` line (silent-write-failures fix) are also uncovered at that
exact call site; `main()`'s shutdown sequence has no test harness in this
codebase at all. The underlying counter method itself is fully tested.

**Why not fixed:** building a `main()`-level test harness is a larger,
cross-cutting testing-infrastructure change, not scoped to any single audit
finding, and no prior fix in this series has built one for its own shutdown
line either.

---

## Re-checked, unchanged from prior work

- **H5 — silent event drops under channel backpressure, uncounted.**
  Unrelated: this is the collectors' own `select { default: /* drop */ }`
  pattern, a different mechanism (buffer-full vs. ordering-race) from H4's.
  Re-confirmed unchanged in all five collectors.
- **H6 — `ml_handoff.md`'s CSV column table.** Documentation-only; unrelated.
- **H7 — PID-reuse aliasing on `pidToSession`.** Unrelated to event-routing
  drops; `handleExec`'s PID lookup logic is untouched.
- **Medium — no `-race`/`test` Makefile target, no CI.** Re-confirmed
  unchanged; this fix's verification was run by hand, same as every prior
  fix in this series.
- **All other Medium/Low items** — re-read, none reference `RouteToSession`,
  `Router`, or `context/architecture.md`'s corrected paragraph; none touched
  by this diff.

---

## Still open, in order of what this unblocks

With H1–H4 now closed, the highest-value remaining items are H5 (uncounted
channel drops across all five collectors — the same "make it visible"
treatment this fix just applied to a different drop mechanism) and H7
(PID-reuse aliasing). H6 is doc-only and lowest-effort whenever picked up.
