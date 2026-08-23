# 2. Tests

This task has an unusual shape for this project's fix series: there is no
single logic bug to redden and then fix. The defect is a coverage/dead-code
mismatch, so the seams are about *what path gets exercised*, not about a new
assertion catching a new kind of wrong output. Eight existing tests were
migrated onto the real path; one new test was added for the one genuinely
new piece of behavior (`Shutdown`).

## Seams — agreed before any test was written

| Seam | Outcome |
|---|---|
| `Detector.Shutdown`'s contract (closes `Completed()` on cancel) | ✅ new, dedicated test |
| Every `Submit*`-driven test, migrated onto a real `Router` | ✅ 7 tests migrated, same assertions |
| The one cross-package test in `internal/output` | ✅ migrated using only `session`'s exported API |
| `Router` itself | unchanged — `router_test.go` already covers it and was not touched |

## `TestDetector_ShutdownClosesCompleted` (renamed from `TestDetector_ContextCancellationClosesCompleted`)

The one piece of new-ish surface: `Detector.Shutdown(ctx)` replaces `Run(ctx)`
for the single behavior production actually depended on. This test asserts
that contract in isolation, with no `Router` and no events at all — `Shutdown`
never touches event state, so testing it standalone is the correct scope, not
a shortcut.

Renamed because it now names the method it tests; keeping the old name after
the method it referenced (`Run`) no longer exists would read as testing
something that isn't there.

**Result: passes**, unsurprising for a two-line method, but this is the test
that would catch a regression if `Shutdown`'s single job were ever broken.

## The seven migrated tests

`TestDetector_NpmInstallLifecycle`, `TestDetector_ConcurrentSessionCwds`,
`TestDetector_SeedsTrackedRootPIDAndCompletesOnRootExit`,
`TestDetector_ForkOnlyChildrenDoNotBlockCompletion`, `TestSessionTimeout`,
`TestDetectorNeverDeliversASessionMoreThanOnceWhenExitRacesTimeout`,
`TestSessionTimeoutClearsItsOwnTimerEntry`, and
`TestDetectorTimedOutStaysFalseWhenExitCompletesBeforeTheTimer` all followed
the same mechanical transformation:

- `detector.Run(ctx)` in its own goroutine → a real `*Router` built over real
  channels (capacities matching the actual collectors: 1024 for process
  events, 4096 for the rest), run via a new shared helper,
  `startDetectorPipeline`, which starts *both* `Router.Run` and
  `Detector.Shutdown` — exactly the two goroutines `cmd/monitor/main.go`
  starts in production.
- `detector.SubmitProcess(ctx, event)` → `procCh <- event`.
- `detector.SubmitSyscall/SubmitFile/SubmitTCP(ctx, event)` → the matching
  channel send (`sysCh <- event`, etc.), used only by
  `TestDetector_NpmInstallLifecycle`, the one test exercising all four event
  types.

No assertion in any of these eight tests changed. Every one still checks
exactly what it checked before — session state, delivery counts, timer
cleanup, `TimedOut` values — the only thing that changed is *how the event
reaches the detector*.

**Result: all eight pass**, unchanged assertions, now via the real path.
Confirmed not just once: `go test -race` run five times in a row across both
affected packages with zero failures, since a change to the concurrency
shape (a channel handoff to a separate goroutine, instead of a direct queue
push drained by a different loop) is exactly the kind of change that could
introduce new flakiness if done carelessly.

## Why calling `HandleProcess`/`RouteToSession` directly was rejected as the migration target

The simpler-looking alternative — since `Router.Run`'s process-event case is
just `r.detector.HandleProcess(event)` — was to have tests call
`HandleProcess`/`RouteToSession` directly, skipping channels and a `Router`
entirely. Rejected in favor of a real `Router` for uniformity with
`router_test.go`, which the audit itself points to as the one file already
exercising "the actual production call path": using the same live-`Router`
idiom everywhere means every migrated test also re-exercises `Router.Run`'s
own select loop on every run, and there is exactly one pattern to review
across nine tests (eight migrated plus the new one) instead of two.

## Goal coverage

| Goal | Covered by | Achieved |
|---|---|---|
| 1 — dead machinery removed | Build succeeds without it; grep finds nothing | yes |
| 2 — `Completed()` still closes on shutdown | `TestDetector_ShutdownClosesCompleted` | yes |
| 3 — tests moved onto the real path | All 8 migrated tests, identical assertions | yes |
| 4 — nothing else changes | Full `-race`/root suites; 5 repeated runs, zero flakes | yes |
