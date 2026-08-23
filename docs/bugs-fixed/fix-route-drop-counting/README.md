# Fix — H4: uncounted, silent event drops for unknown PIDs

This directory documents one piece of work: repairing **H4**, the fourth of
the audit's High findings in [`../../AUDIT.md`](../../AUDIT.md), using the
test-driven workflow in `skills/.agents/skills/tdd/`.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written or extended, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | Step by step. |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why counting, not eliminating the race? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-findings-not-fixed.md](07-findings-not-fixed.md) | What was left open. |
| — | [evidence/](evidence/) | Raw, unedited output behind every claim made above. |

## One-paragraph summary

`context/architecture.md` claimed the router's outer-`select` priority for
process events prevents syscall events for a brand-new PID from being
dropped before its session exists. That claim is false: the priority only
helps when a process event is already buffered at the instant `select`
runs, and the five event types arrive via five independent
ring-buffer-reading goroutines with no cross-channel ordering guarantee at
all. When a syscall/file/TCP event for an unregistered PID reaches
`RouteToSession`, it is dropped — silently, permanently, with no counter, no
log, and no retry.

Eliminating the race itself would need a retry buffer or a timestamp-based
reorder mechanism across all five streams — real architectural additions the
audit doesn't ask for and this project's fix series has consistently avoided
in favor of narrower, defensive changes (see H2's `pending_opens`
insert-failure counter for the precedent). This fix instead makes the drop
visible: a `DroppedRoutesForUnknownPID()` counter, a verbose-mode log line at
the drop site, a shutdown report in `cmd/monitor`, and a corrected
`context/architecture.md` that states the true, narrower guarantee.

## What shipped

- `Detector.DroppedRoutesForUnknownPID() uint64` — an atomic counter,
  incremented every time `RouteToSession` finds no session for a PID.
- A verbose-mode log line at the same drop site (`d.logf(...)`), closing "no
  log by default."
- `cmd/monitor` reports a nonzero count at shutdown, matching the shape of
  the existing `pending_opens`/`LOST N of M session(s)` reports.
- `context/architecture.md`'s false claim rewritten to state what the
  priority pattern actually guarantees (narrows the odds, does not
  eliminate the race) and to point at this fix.
- `TestRouter_UnknownPID` extended with a count assertion — proving the
  counter increments through the real `Router`-driven path, not a synthetic
  shortcut — plus a new unit test,
  `TestRouteToSessionCountsAndLogsDropsForUnknownPID`, pinning the counter
  and logger contract directly, including a negative check for known PIDs.
