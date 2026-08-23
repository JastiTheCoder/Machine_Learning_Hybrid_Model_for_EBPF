# 5. Why this approach

## Why removal, not completion (adding `SubmitBytes` and wiring `Run()` in)

The audit itself notes the asymmetry: `Detector.Run()`/`Submit*` has no
`SubmitBytes`/`bytesEvents` counterpart, "a leftover from before
`BytesCollector` existed, never fully wired up or removed." The alternative
to deleting this machinery would be finishing it — adding `SubmitBytes`, and
switching `cmd/monitor/main.go` to feed `Detector.Run()` via `Submit*` calls
instead of wiring `Router` directly.

Rejected outright: `Router` already does this job, correctly, with test
coverage of its own (`router_test.go`) that the `Submit*`/`Run()` path never
had for the harder cases (`TestRouter_UnknownPID`, `TestRouter_RaceConditions`).
Completing the parallel mechanism would mean maintaining two independent
implementations of "get an event to `HandleProcess`/`RouteToSession`"
indefinitely, doubling the surface for exactly the kind of drift that
produced H3 in the first place. Deleting the one nothing uses is strictly
smaller and strictly safer than making the unused one whole.

## Why `Shutdown` is a separate method, not folded into `Router.Run`

The alternative considered: have `Router.Run` itself call
`d.closeCompletedSessions()` when it returns, removing the need for a second
goroutine entirely. Rejected for two reasons:

1. **It changes `Router`'s contract**, a type this task's goal explicitly
   excludes from changing ("nothing else changes" — see [01-goals.md](01-goals.md)
   goal 4). `Router` currently has no dependency on `Detector`'s completed-
   channel lifecycle beyond calling `HandleProcess`/`RouteToSession`; giving
   it one more responsibility widens what it's for.
2. **It would not generalize.** `cmd/monitor/main.go` could, in principle,
   run without a `Router` at all (a future caller driving `HandleProcess`
   some other way) and would still need `Completed()` closed on shutdown.
   Keeping the responsibility on `Detector` itself — the type that owns
   `completedSessions` — means the shutdown contract doesn't depend on which
   caller happens to be feeding it events.

A tiny, single-purpose method that only `Detector` needs to get right is the
same shape this project has favored before: `Session.Snapshot()` (C2) and
`Session.MarkCompleteOnce()` (C3) are both narrow methods on the type that
owns the state, rather than a responsibility pushed onto a caller.

## Why every migrated test uses a real `Router`, not a mock or a direct call

Covered in [02-tests.md](02-tests.md)'s "why calling `HandleProcess`/
`RouteToSession` directly was rejected" — restated briefly here: a real
`Router` over real channels is the literal production wiring, not an
approximation of it. Since `router_test.go` already establishes this as the
project's idiom for testing this boundary, using it everywhere means there
is exactly one way this package tests detector event delivery, not two
competing ones of different fidelity.

## Why this was a same-package + one-cross-package-test fix, not a `Router` rewrite

An alternative framing of H3 would be "the router's priority-select pattern
is duplicated between `Router.Run` and the now-dead `Detector.Run` — unify
them." Rejected: `Detector.Run`'s copy of that pattern is being deleted
entirely, not merged into `Router`, so there is nothing left to unify.
`Router`'s own priority-select pattern is the subject of a separate,
already-filed audit finding (H4, "Router's priority pattern doesn't
guarantee the ordering the docs claim it does") and touching it here would
violate this task's own scope boundary — see
[07-findings-not-fixed.md](07-findings-not-fixed.md).
