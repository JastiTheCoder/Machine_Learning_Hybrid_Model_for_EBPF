# 2. Tests

One new unit test, one existing test extended. Both are genuinely red
against the pre-fix code (a compile error, since the accessor method didn't
exist), and both pass unchanged once the fix lands.

## Seams — agreed before any test was written

| Seam | Outcome |
|---|---|
| `RouteToSession`'s own contract, called directly (no `Router`) | ✅ new test, with a negative check |
| The real `Router`-driven path, for an unknown PID | ✅ extended `TestRouter_UnknownPID` |
| `Router.Run`'s select structure itself | not touched — out of scope (see [01-goals.md](01-goals.md)) |

## `TestRouteToSessionCountsAndLogsDropsForUnknownPID` (new)

Calls `RouteToSession` directly for a PID with no registered session, three
times, and asserts:

1. `DroppedRoutesForUnknownPID()` reads `3` afterward.
2. A configured verbose logger (`SetLogger`) received exactly three lines,
   each mentioning the dropped PID.
3. **The negative check that gives this test teeth**: a fourth call for a
   *registered* PID must call the provided closure, and must leave both the
   counter and the logged-line count unchanged. A naive implementation that
   always increments (regardless of whether a session was found) would pass
   the first two assertions and fail this one.

**Result: achieved.**

Red (against pre-fix `detector.go`, which has no `DroppedRoutesForUnknownPID`
method at all):

```
internal/session/detector_test.go:820:21: detector.DroppedRoutesForUnknownPID undefined
internal/session/detector_test.go:832:21: detector.DroppedRoutesForUnknownPID undefined
internal/session/detector_test.go:855:21: detector.DroppedRoutesForUnknownPID undefined
internal/session/router_test.go:203:21: detector.DroppedRoutesForUnknownPID undefined
FAIL	github.com/aniruddha/npm-ebpf-monitor/internal/session [build failed]
```

Green: both new assertions and the extended `TestRouter_UnknownPID` (below)
pass together, since `DroppedRoutesForUnknownPID` didn't exist as a symbol at
all — a single build failure covers both tests, consistent with how this
project has treated "new API + new behavior" reds before (see the C3 fix's
`MarkCompleteOnce undefined`).

Raw: [`red.txt`](evidence/red.txt), [`green.txt`](evidence/green.txt).

## `TestRouter_UnknownPID` (extended, not new)

This existing test already drives exactly the audit's scenario: syscall,
file, and TCP events for PID `999`, with no session ever registered for it,
through a real `Router`. It already asserted the events had no effect
(`syscallCount == 0`, etc.) and that PID `999` was never attached to a
session. One assertion added:

```go
if got := detector.DroppedRoutesForUnknownPID(); got != 3 {
    t.Fatalf("DroppedRoutesForUnknownPID() = %d, want 3 (syscall + file + tcp, all pid 999)", got)
}
```

This is deliberately the stronger seam of the two: it proves the counter
increments through the *real* `Router.Run` select loop and the *real*
`RouteToSession` call `Router` makes — not a synthetic direct call — which is
exactly the path H4 says silently drops events in production.

**Result: achieved.**

## Goal coverage

| Goal | Covered by | Achieved |
|---|---|---|
| 1 — doc claim corrected | `context/architecture.md` diff (see [03-what-was-done.md](03-what-was-done.md)) | yes |
| 2 — drop counted | Both tests | yes |
| 3 — drop logged when verbose | New test's logger assertions | yes |
| 4 — reported at shutdown | `cmd/monitor/main.go` change, not itself unit-tested (see [07-findings-not-fixed.md](07-findings-not-fixed.md)) | yes (code), partial (test coverage) |
| 5 — nothing else changes | `router.go` untouched; full `-race`/root suites green | yes |
