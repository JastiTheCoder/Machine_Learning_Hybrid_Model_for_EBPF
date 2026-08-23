# 7. Findings not fixed

A fresh re-check of `AUDIT.md` against the repository as it stands after this
work — not a copy of an earlier list. Re-verification was done by reading
current source directly (grep + line-range reads), not by trusting a prior
doc's line numbers or historical commit labels, per this session's own
earlier finding that `AUDIT.md`'s numbering has drifted from what some older
`docs/bugs-fixed/*` commit messages call the same items.

## The `FileEvent.TimestampNs` alignment bug is not a finding left open — it is fixed by this work

Stated explicitly so it is not mistaken for an item on this list: the
`binary.Read`/C-struct-alignment corruption of `FileEvent.TimestampNs`
(discovered while building this task's own end-to-end test) is documented in
[02-tests.md](02-tests.md) and [03-what-was-done.md](03-what-was-done.md) as
**shipped and verified**, both at the decode level (no root) and under a
real kernel load/run (root-gated). It is not an `AUDIT.md` item — it was
found by this task, in code this task's own Stage 1 and Stage 9 work built
and depends on — and it is fixed, not deferred. See
[05-why-this-approach.md](05-why-this-approach.md) for why fixing it here,
rather than filing it separately, was judged in scope.

## A. The system-wide-tracing / evidence-misattribution finding — real, still unfixed, and this session's own theory of its mechanism was partially wrong

An earlier stage of this same overall session's work produced a captured
session where a provably-innocent fixture scored `malicious` with
evidence that did not match anything the fixture itself did. That
observation is real and remains unexplained in full. What changed this
session is the theory of *why*.

The earlier working theory was, in effect, "the collectors trace
system-wide and filter only after the fact, so an unrelated concurrent
process's activity can leak into a session's evidence." That mechanism was
checked directly this session and does **not** hold as stated:

```
$ grep -n "is_tracked\|tracked_pids" bpf/file_monitor.bpf.c bpf/tcp_monitor.bpf.c
```

confirms both programs call `is_tracked(tgid)` and return early (before any
ring-buffer reservation) for any PID not present in the shared
`tracked_pids` map — filtering happens in-kernel, before an event is ever
emitted, not in userspace after the fact. A naive "trace everything, filter
later" design is not what is actually implemented.

**What this does not rule out**, and was not re-diagnosed to a conclusion
this session: `tracked_pids` filtering being *correct in kernel* does not
mean the *set of tracked PIDs itself* is always correct in userspace. H7
below (`pidToSession` PID-reuse aliasing) is the most plausible remaining
mechanism — if a tracked child PID exits and the kernel recycles that PID
number to an unrelated process before `tracked_pids`/`pidToSession` are
cleaned up, events from the unrelated process would be both correctly
kernel-filtered (the PID *is* in `tracked_pids`) and incorrectly attributed
(to the wrong session) in userspace. This is a plausible, not confirmed,
explanation — it was not instrumented or reproduced this session, and
should not be stated as settled.

**Why not fixed here:** confirming or ruling out the PID-reuse-aliasing
mechanism requires either a targeted reproduction (force a PID to be
recycled during an active capture window) or a fuller audit trail linking a
misattributed session's evidence back to the actual originating PID and
timestamp — neither is a small addition to this task, and H7 is a distinct,
already-tracked `AUDIT.md` item that deserves its own scoped fix rather than
a partial one bundled into this task's verdict-engine work.

## B. Evidence caps interact with H5 — new nuance from this work, not previously stated this way

`EvidenceCollector`'s 32-entry caps (`comms`, `endpoints`) mean a session
that drops events under H5's channel backpressure (see below) can also lose
the specific evidence a decisive rule needed, silently, on top of losing
whatever feature counts H5 already affected. `Evidence.Truncated` surfaces a
cap having been hit; it does not distinguish "capped because 33 distinct
paths were genuinely opened" from "capped early because some events were
dropped before they arrived." This was flagged as a known limitation in the
approved plan and is recorded here as still true, not newly discovered.

---

## Re-checked against current source, not copied from a prior doc

- **H3 — `Detector.Run()`/`Submit*` dead in production.** Re-confirmed
  **fixed** (by prior work in this session, not this task):
  `grep -n "detector.Run(\|\.Submit(" cmd/monitor/main.go` returns no
  matches. `cmd/monitor/main.go` wires `router.Run(ctx)` only; the router
  calls `detector.HandleProcess`/`RouteToSession` directly.
- **H5 — uncounted channel drops across all 5 collectors.** Re-confirmed
  **fixed** (by prior work): `grep -rln "DroppedEvents\|dropCount"
  internal/collector/*.go` (excluding tests) matches all five collector
  files — `bytes_collector.go`, `tcp_collector.go`, `file_collector.go`,
  `process_collector.go`, `syscall_collector.go`.
- **H4 — router priority pattern doesn't guarantee cross-channel ordering.**
  Re-confirmed **still open**: `internal/session/router.go`'s `Run` still has
  the exact outer/inner `select` shape the finding describes — an outer
  `select` checks only `ctx.Done()` and `procCh`, falling to `default:` only
  when `procCh` has nothing immediately ready, and the inner `select` then
  treats `procCh`, `sysCh`, `fileCh`, `tcpCh`, `bytesCh` with no priority
  among them. Untouched by this task; irrelevant to the verdict engine's own
  correctness since `Evaluate` is a pure function of whatever evidence
  eventually lands in a `Snapshot()`, not of arrival order across channels
  (only *within* file-event timestamps, via `firstSeen`, which is
  independent of router ordering).
- **H6 — `ml_handoff.md`'s CSV column table is self-contradictory.**
  Re-confirmed **still open**: `docs/misc/ml_handoff.md` still has the
  phantom `unknown_ops` row (column 29) and the garbled final-row labeling
  (`39–1: p10_error_handle` then `severity_score`), with its own inline
  `> **Note:**` acknowledging the contradiction rather than resolving it.
  Documentation-only; untouched by this task, and this task's own 39-column
  CSV export is unaffected (`TestToCSVRowStillHas39ColumnsWithVerdictAttached`).
- **H7 — PID-reuse aliasing on `pidToSession`.** Re-confirmed **still open**:
  `pidToSession map[uint32]*Session` (`internal/session/detector.go:28`) is
  still a plain map with no epoch or generation guard against PID reuse.
  Newly relevant this session as the most plausible (not confirmed)
  mechanism behind finding A above.
- **Medium — `unregisterSession`'s linear scan.** Re-confirmed **still
  open**: `internal/session/detector.go:351-362`, `unregisterSession` still
  does `for pid, mapped := range d.pidToSession { if mapped == session {
  delete(...) } }` under `d.mu.Lock()`. Untouched; not on this task's
  critical path (the verdict engine reads a `Session` after it is already
  complete, never touches `pidToSession` directly).
- **Medium/Low — no CI, stale toolchain pins, double BPF-object loads, and
  the remainder of `AUDIT.md`'s Medium/Low items.** Re-read; none reference
  `internal/verdict`, `internal/features/evidence.go`, or the `pending_open`
  filename field; none touched by this task.

---

## Still open, in order of what this unblocks next

H7 is now the most directly relevant item to this task's own domain: it is
the leading unconfirmed explanation for finding A (evidence
misattribution), which directly undermines trust in the verdict engine this
task just built — a `malicious` verdict is only as trustworthy as the
evidence it was computed from actually belonging to the session it's
attached to. H4 and H5's interaction (finding B above) is the second
priority, since it means a dropped-event corpus can silently degrade a
decisive rule's own inputs without any visible signal beyond
`Evidence.Truncated`. H6 remains a pure documentation fix, isolated from
runtime correctness, and is the lowest priority of the group.
