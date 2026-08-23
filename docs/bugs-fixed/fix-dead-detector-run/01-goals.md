# 1. Goals

## The defect

`AUDIT.md` H3, verbatim:

> `cmd/monitor/main.go` starts both `detector.Run(ctx)` and `router.Run(ctx)`.
> But `Router.Run` calls `detector.HandleProcess`/`detector.RouteToSession`
> **directly**, never through `Detector`'s
> `SubmitProcess/SubmitSyscall/SubmitFile/SubmitTCP` methods. A repo-wide grep
> confirms those `Submit*` methods are called only from `detector_test.go` —
> never from production code. `Detector.Run()`'s internal event channels are
> therefore never fed in production; that goroutine just blocks on
> `ctx.Done()` forever.
>
> The consequence for test coverage: `TestDetector_NpmInstallLifecycle`,
> `TestDetector_ConcurrentSessionCwds`,
> `TestDetector_SeedsTrackedRootPIDAndCompletesOnRootExit`,
> `TestDetector_ForkOnlyChildrenDoNotBlockCompletion`, and `TestSessionTimeout`
> all drive the detector via `Submit*` + `detector.Run(ctx)` — a path the real
> binary never executes. Only `router_test.go` exercises the actual
> production call path, and its lifecycle-edge-case coverage (timeout races,
> fork-then-immediate-exit, PID reuse) is much thinner. This also means
> there's no `SubmitBytes`/`bytesEvents` in `Detector` at all — a leftover
> from before `BytesCollector` existed, never fully wired up or removed.

Verified by grep before changing anything (raw output in
[`evidence/pre-removal-caller-grep.txt`](evidence/pre-removal-caller-grep.txt)):
`SubmitProcess`/`SubmitSyscall`/`SubmitFile`/`SubmitTCP` had exactly zero
non-test callers; `detector.Run(ctx)` had exactly one caller, a single
`startTrackedGoroutine` line in `cmd/monitor/main.go`.

Three additional tests turned out to depend on this same dead path, beyond
the five the audit named: `TestDetector_ContextCancellationClosesCompleted`
and the three tests added by this project's own C3 fix
(`TestDetectorNeverDeliversASessionMoreThanOnceWhenExitRacesTimeout`,
`TestSessionTimeoutClearsItsOwnTimerEntry`,
`TestDetectorTimedOutStaysFalseWhenExitCompletesBeforeTheTimer`) — plus one
more in a different package entirely,
`TestBuildRecordOnCompletedSessionWhileCollectorsStillWrite` in
`internal/output/json_writer_test.go`, from the C2 fix. Eight tests total,
across two packages, exercising a code path production never runs.

## A subtlety the audit's wording doesn't quite capture

`Detector.Run()`'s internal event channels are indeed never fed — but the
method is not *entirely* inert. Its `defer d.closeCompletedSessions()` runs
when `ctx.Done()` fires, and `cmd/monitor`'s output worker does
`for completed := range detector.Completed()` — a loop that only terminates
when that channel is *closed*. Removing `Run()` outright, with nothing
replacing this side effect, would have left the output worker's goroutine
blocked forever on shutdown, breaking `cmd/monitor`'s graceful-shutdown path
entirely. This was caught by reading `Run()`'s body and `runOutputWorker`'s
loop together before writing any code, not discovered by a failing test.

## Goals

1. **Remove the dead machinery** — `Run()`, `SubmitProcess`, `SubmitSyscall`,
   `SubmitFile`, `SubmitTCP`, and their four backing channels — since none of
   it has a production caller and it cannot be completed (no `SubmitBytes`
   exists, and none should be added) without contradicting the fact that
   `Router` already does this job correctly.
2. **Preserve the one real behavior `Run()` provided**: closing
   `Completed()` when the context is canceled, so `cmd/monitor`'s output
   worker still terminates on shutdown.
3. **Migrate every affected test onto the real production path** — a live
   `Router` over real channels, exactly as `cmd/monitor/main.go` wires it —
   so what is tested is what ships.
4. **Nothing else changes**: no change to `HandleProcess`, `RouteToSession`,
   any `handle*` method, `Router.Run`, session/output/BPF code, or any test's
   assertions.

## How we would know

- Goal 1 → the build succeeds with `Submit*`/`Run()` deleted from
  `detector.go`; a repo-wide grep finds no remaining references.
- Goal 2 → a dedicated test (`TestDetector_ShutdownClosesCompleted`) proving
  the replacement method's entire contract, plus the existing
  `TestRunOutputWorkerReportsWriteOutcomes`'s "no sessions at all" case,
  which already depends on a closed channel to terminate its `for range`.
- Goal 3 → all eight affected tests, migrated to build a real `Router` (or
  call `Shutdown` directly where no event delivery is involved), passing
  with their original assertions unchanged.
- Goal 4 → full repository suite, `-race` and under root, plus five repeated
  runs of the migrated packages to rule out new flakiness from the changed
  concurrency shape.
