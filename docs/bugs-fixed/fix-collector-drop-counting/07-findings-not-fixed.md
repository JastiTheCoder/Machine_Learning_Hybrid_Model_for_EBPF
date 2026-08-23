# 7. Findings not fixed

A fresh re-check of `AUDIT.md` against the repository's current state after
this fix — not a copy of the original list. Checked against `HEAD` (the
last commit on `fix/audit-critical-findings`) plus this fix's own diff; the
working tree also carries a large amount of unrelated, uncommitted change
outside this fix's scope (ML-side feature/aggregator files, dataset
scripts, session fixtures, a deleted `docs/ml_handoff.md`, mode-only changes
to a few `bpf/*.c` files and `internal/collector/collector.go`) that this
fix does not touch, does not stage, and this re-check does not evaluate —
see the note at the end.

## A. The underlying channel backpressure is not eliminated — by design, stated up front

This fix makes every collector's drop visible; it does not close the window
that causes it. See [01-goals.md](01-goals.md) and
[05-why-this-approach.md](05-why-this-approach.md) for why a
resize/backoff/overflow-buffer redesign was rejected as disproportionate to
what H5 actually asks for.

## B. `ProcessCollector`'s missing `is_tracked()` gate — new observation, not fixed

`process_tracer.bpf.c`'s `sys_enter_execve` handler emits an event for
every execve() on the machine, unconditionally, unlike the other four
collectors' BPF programs which all gate on `is_tracked()`. This was
discovered while fixing this task's own test (see
[04-how-it-was-done.md](04-how-it-was-done.md)) and is real: on a busy
machine, `ProcessCollector.Events` can fill with unrelated system exec
noise and start dropping *before any npm install even begins*, making it
the sharpest version of H5 among the five collectors. This is architectural
by necessity — tracking a PID can only start at its own exec event, so
gating that specific event on `is_tracked()` would either miss the first
event of every tracked process (defeating the collector's purpose) or need
new special-case logic distinguishing "the exec that starts tracking" from
everything else. `AUDIT.md`'s H5 text names the shared `select`/`default`
drop pattern across all five collectors; it does not name this asymmetry
specifically. Extending this fix to change `ProcessCollector`'s emission
gating would be a production behavior change outside this task's literal
scope per `CLAUDE.md` ("fix ONLY the vulnerability specified... do not fix
other unfixed AUDIT.md items in this session, even if related or
tempting"). **If it's ever worth addressing:** the `DroppedEvents()` counter
this fix adds already makes the resulting drop rate observable in
production; whether it's material enough to justify a design change is now
a measurable question rather than a guess.

## C. Test coverage — partially mitigated as a side effect

`AUDIT.md`'s "Test coverage gaps" table originally read: *"`syscall_collector.go`,
`file_collector.go`, `tcp_collector.go`, `bytes_collector.go` — No tests at
all (only `process_collector_test.go` has a struct-layout assertion)."*
That's now stale. All four have exactly one test each, added by this fix
(`TestFileCollectorCountsDroppedEvents`,
`TestSyscallCollectorCountsDroppedEvents`,
`TestTcpCollectorCountsDroppedEvents`,
`TestBytesCollectorCountsDroppedEvents`) — but each is narrowly scoped to
H5's own drop-counting behavior. None of these four collectors have tests
for their actual decode/attach/lifecycle logic the way
`process_collector_test.go` and `file_collector_test.go` already did before
this fix (e.g. `TestProcessCollectorReportsForkOfTrackedProcess`,
`TestFileCollectorReportsOpenFlagsFromRealOpenat`). Writing that broader
coverage for `syscall_collector.go`, `tcp_collector.go`, and
`bytes_collector.go` is real, worthwhile follow-up work, but is out of this
task's scope — adding it here would be exactly the kind of drive-by
`CLAUDE.md` asks not to do.

## D. No `cmd/monitor`-level test for the shutdown report line itself

`cmd/monitor/main.go`'s new H5 shutdown loop is not covered by an automated
test — consistent with how the sibling `pending_opens` (H2) and
`DroppedRoutesForUnknownPID` (H4) shutdown lines are also untested;
`main()`-level reporting has no test harness anywhere in this codebase.

## Re-checked, unrelated to this fix

- **H6 — `docs/ml_handoff.md`'s CSV column table.** File exists and is
  unchanged at `HEAD` (it appears deleted in the current dirty working
  tree, but that's outside this fix — see the note below). Documentation-only,
  unrelated to collector code.
- **H7 — PID-reuse aliasing on `pidToSession`.** Unrelated to collector-level
  channel drops; `handleExec`'s PID lookup logic (`internal/session/detector.go`)
  is untouched by this fix. Note that this fix's `DroppedEvents()` counters
  now make H7's own precondition (a dropped EXIT event) directly observable
  where it previously wasn't — useful context for whoever picks up H7 next,
  but H7 itself is not fixed here.
- **Medium — `internal/output/writer.go` dead stub.** Re-confirmed unchanged
  at `HEAD`: `NewWriter`/`WriteResults` still have no callers anywhere in
  the codebase and `WriteResults` still unconditionally returns `nil`.
- **Medium — `aggregator.go`/`collector.go` dead `TODO` stubs.** Re-confirmed
  unchanged at `HEAD` (`internal/collector/collector.go`'s working-tree diff
  is a permission-mode change only, `0644`→`0755`, with zero content diff —
  not part of this fix, not evaluated further here).
- **Medium — stale binary name in `compare_packages.sh`/`compare_packages_multi.sh`.**
  Re-confirmed unchanged at `HEAD`: both still hardcode
  `BINARY="$PROJECT_ROOT/npm-ebpf-monitor"` against an actual build output
  named `monitor`.
- **Medium — `Makefile clean` target cleans the wrong directory.** Re-confirmed
  unchanged at `HEAD`.
- **Medium — pinned toolchain variables never wired in.** Re-confirmed
  unchanged at `HEAD`: `CLANG`/`LLVM_STRIP` are still declared, still
  unreferenced by the `generate` target.
- **Medium — `TcpCollector`/`BytesCollector` double-load the same BPF object.**
  Re-confirmed unchanged — this fix's `dropCount` field is per-collector-struct,
  not per-loaded-object, so it doesn't interact with this waste at all.
- **Medium — `InstallExtractor` discards results on partial parse error,
  `isNpmInstallInvocation`'s loose substring match, `unregisterSession`'s
  linear scan, no `-race`/`test` Makefile target or CI, `test_tcp_direct.go`
  sitting at the module root with no build tag.** All re-confirmed present
  and unchanged; none reference any of the five collectors' `Events`
  channels, `dropCount`, or `cmd/monitor`'s new report block.
- **All Low items** — re-read in full; none reference collector drop
  handling, `DroppedEvents`, or the shutdown report added here.

## Note on the dirty working tree

`git status` currently shows ~68 modified/deleted/untracked paths this fix
does not touch — `internal/features/*.go` (ML-side aggregators/counters),
`internal/output/writer.go`/`validator.go`, `internal/session/router.go`,
`Makefile`, `README.md`, `go.mod`/`go.sum`, several `sessions/*.json`
fixtures, `docs/ml_handoff.md` (deleted), and others. None of this is part
of H5 or was produced by this task; it is left exactly as found, not staged,
not committed, and not evaluated against `AUDIT.md` here, per this task's
scope and per `CLAUDE.md`'s ML-model exclusion. Worth flagging to the repo
owner separately, since it's a large amount of uncommitted state sitting in
the working tree outside version control's safety net.

---

## Still open, in priority order

With H1–H5 now closed, the highest-value remaining items are **H7**
(PID-reuse aliasing — now more directly reachable given H5's counters
expose real EXIT-drop rates for the first time) and **B above**
(`ProcessCollector`'s unconditional exec emission, if its measured drop
rate in real use ever turns out to matter). **H6** (the `ml_handoff.md`
doc-only table) remains the lowest-effort item whenever picked up.
