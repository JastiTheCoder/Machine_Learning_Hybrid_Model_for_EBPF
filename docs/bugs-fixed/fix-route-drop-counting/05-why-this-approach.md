# 5. Why this approach

## Why counting, not a retry/reorder buffer

The alternative that would actually *close* the race, rather than make it
visible, is some form of holding events for an unrecognized PID briefly and
retrying once its session registers (or reordering all five streams by their
kernel timestamp before dispatch, since every event already carries
`bpf_ktime_get_ns()`). Both were considered and rejected:

- **A retry buffer** needs a new stateful subsystem: a bounded per-PID queue,
  an expiry sweep, and replay logic wired into every place a PID gets
  associated with a session (`registerSession`, `associatePID`, `trackPID`).
  That is real new surface with its own correctness questions (unbounded
  growth if abused, concurrency between "replay on registration" and "expire
  on timeout") for a project whose fix series has consistently favored small,
  narrow, defensive changes over new subsystems — see H2's decision to count
  `pending_opens` insert failures rather than add capacity management, or the
  C2/C3 fixes' preference for a single new method (`Snapshot`,
  `MarkCompleteOnce`) over a broader redesign.
- **A timestamp-reorder buffer** would add latency to *every* event, not just
  the rare racing ones, changing this pipeline's performance characteristics
  wholesale to fix a corner case. It would also need to pick a maximum
  reordering window — too short and it doesn't help, too long and it delays
  every session's feature collection by that amount.

The audit's own framing supports the narrower fix: it states the race exists
"regardless of the select structure" and never asks for elimination, only
naming "no retry, no counter, no log" as evidence of how invisible the
current drop is. Making it counted and, in verbose mode, logged, directly
answers that — converting an invisible defect into a measured, bounded one,
which is itself real information for anyone debugging an undercounted
session's features.

## Why `sync/atomic` rather than `d.mu`

`RouteToSession` already takes `d.mu.RLock()` (a *read* lock) to look up
`d.pidToSession[pid]`. Incrementing a shared counter under a read lock is a
data race; the alternative would be upgrading to `d.mu.Lock()` (the write
lock) for every routed call, including the overwhelming majority that
successfully find a session — a real throughput cost on this package's
hottest path, imposed to protect a value that's wrong to write under a read
lock in the first place. `sync/atomic` gives the counter its own
synchronization, independent of `d.mu`, at the cost of one atomic add per
drop (not per successful route) — a fair trade given drops should be rare in
practice.

## Why `context/architecture.md` was corrected here, not left for a later task

H3's own findings-not-fixed explicitly deferred a *different* stale claim in
this same file (about `Detector.Run`), reasoning that the file "is not owned
exclusively by this fix" and pointing at H4 as the task whose scope actually
covers that file's accuracy. That reasoning cuts the other way for the claim
H4 itself names: this *is* the task whose primary subject is that paragraph.
Leaving it stale here, on the grounds that the file lives outside
`npm-ebpf-monitor/`, would mean no fix in this entire series ever corrects
it — the file's location doesn't change which finding it belongs to.

## Why the negative check (known PID) was in the test from the start, not added after

A counter that increments on every `RouteToSession` call, regardless of
whether a session was found, is a plausible wrong-but-passing first
implementation: it would satisfy "counted" without actually measuring what
the audit describes (drops specifically for *unknown* PIDs). Writing the
negative check as part of the same test, rather than as an afterthought, is
what turns "the counter goes up" into "the counter goes up for the right
reason" — the same discipline behind every "checked for teeth" step in this
project's prior fixes, applied at write-time here instead of via a separate
revert-and-rerun pass, since the assertion was cheap enough to include
directly.
