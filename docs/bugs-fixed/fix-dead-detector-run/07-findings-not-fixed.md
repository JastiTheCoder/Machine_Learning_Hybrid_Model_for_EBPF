# 7. Findings not fixed

A fresh re-check of `AUDIT.md` against the repository as it stands after this
fix — not a copy of the original list.

## A. The audit's own "Test coverage gaps" table row is now resolved as a side effect

`AUDIT.md`'s test coverage table lists: *"Session lifecycle (exec/fork/exit)
| Tested, but mostly via the **dead** `Submit*`/`Detector.Run` path (H3), not
the real `Router`→`Detector` production path."* Re-checked directly: this row
describes exactly what this task fixed. All eight previously-dead-path tests
now drive the real `Router`→`Detector` path. This table row can be marked
resolved alongside H3 — it was never a separate finding, just the audit's own
note of H3's downstream effect on its coverage-gap accounting.

## B. `context/architecture.md` still documents the removed `Run()`/channel design

`/home/ani/capstone/context/architecture.md:479` has a table row: `| 6 |
Detector.Run | internal event channels | completedSessions chan *Session |`
— describing the exact machinery this task removed.

**Why not fixed:** this file lives outside `npm-ebpf-monitor/` entirely, in
the top-level project's shared `context/` directory (explicitly listed in
`CLAUDE.md` as reference material, not a file this task's scope covers), and
is not owned exclusively by this fix. `AUDIT.md`'s own H4 already documents a
separate, unrelated staleness in the same file (`context/architecture.md`'s
router-priority claims), which no prior fix in this series has touched for
the same reason — consistent with leaving cross-cutting doc drift to
whichever task actually addresses that file's accuracy as its primary
subject, rather than each fix patching one more stale line in passing.

**If it ever needs closing:** update the table row (and, while there, H4's
router-priority claim) together, since both are in the same file and the
same "confirm the diagram against the current code" pass would catch both.

## C. `docs/architecture_deep_dive.md` (this project's own copy) was not checked

Unlike `context/architecture.md` above, `docs/architecture_deep_dive.md`
lives inside `npm-ebpf-monitor/` itself. Checked: it does not mention
`Detector.Run`, `Submit*`, or the internal event channels by name, so no
correction is needed there.

---

## Re-checked, unchanged from prior work

- **H4 — router priority pattern doesn't guarantee cross-channel ordering.**
  Unrelated to this fix; `Router.Run`'s select structure is untouched.
  Re-confirmed by reading `router.go` in full while designing
  `startDetectorPipeline` — no changes were made to it.
- **H5 — silent event drops under channel backpressure, uncounted.**
  Unrelated; the collectors' own `select { default: /* drop */ }` pattern is
  untouched. The new test-local channels this fix adds
  (`procCh`/`sysCh`/`fileCh`/`tcpCh` in migrated tests) are unbuffered-safe
  sends in a controlled test, not collector-facing code, so they carry no
  H5 exposure of their own.
- **H6 — `ml_handoff.md`'s CSV column table.** Documentation-only; unrelated.
- **H7 — PID-reuse aliasing on `pidToSession`.** Unrelated to event-delivery
  plumbing; `handleExec`'s PID lookup logic is untouched.
- **Medium — no `-race`/`test` Makefile target, no CI.** Re-confirmed
  unchanged; this fix's verification was run by hand, same as every prior
  fix in this series.
- **All other Medium/Low items** — re-read, none reference `Detector.Run`,
  `Submit*`, or `Router`; none touched by this diff.

---

## Still open, in order of what this unblocks

With H1, H2, and H3 now closed, the highest-value remaining items are H4
(router ordering guarantees), H5 (uncounted channel drops across all five
collectors), H6 (doc-only), and H7 (PID-reuse aliasing). H5 and H7 remain
the two most directly relevant to a long, high-throughput capture run, as
noted in the previous fix's findings-not-fixed. H4 is now more tractable to
address than before this task: with `Detector.Run()`'s duplicate
priority-select pattern gone, `Router.Run` is the *only* place that pattern
exists in this codebase, so a future fix has one implementation to reason
about instead of two.
