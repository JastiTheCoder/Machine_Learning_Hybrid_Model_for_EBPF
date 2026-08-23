# 3. What was done

Two production files changed, two test files migrated.

## `internal/session/detector.go` — remove the dead API, add its one real replacement

Removed from the `Detector` struct: `processEvents`, `syscallEvents`,
`fileEvents`, `tcpEvents` (all four `chan collector.XxxEvent` fields), and
their initialization in `NewDetector`. Removed entirely: `Run(ctx)`,
`SubmitProcess`, `SubmitSyscall`, `SubmitFile`, `SubmitTCP`.

Added in `Run`'s place:

```go
// Shutdown blocks until ctx is canceled, then closes the Completed() channel.
//
// Event delivery itself happens through HandleProcess and RouteToSession,
// called directly by Router.Run -- this method's only job is the one
// production actually needs from a long-lived detector goroutine: knowing
// when to close Completed() so a consumer ranging over it (cmd/monitor's
// output worker) terminates cleanly on shutdown, rather than blocking
// forever. Run it in its own goroutine alongside Router.Run:
//
//	go detector.Shutdown(ctx)
//	go router.Run(ctx)
func (d *Detector) Shutdown(ctx context.Context) {
	<-ctx.Done()
	d.closeCompletedSessions()
}
```

`HandleProcess` and `RouteToSession` — the two methods `Router.Run` already
called directly — are untouched.

## `cmd/monitor/main.go` — one call-site change

```diff
-	startTrackedGoroutine(&wg, func() { detector.Run(ctx) })
+	startTrackedGoroutine(&wg, func() { detector.Shutdown(ctx) })
```

`router.Run(ctx)` on the next line is unchanged — it was already the real
production path.

## `internal/session/detector_test.go` — migrate eight tests, add one helper

Added `startDetectorPipeline(router *Router, detector *Detector, ctx
context.Context) <-chan struct{}`, which starts `Router.Run` and
`Detector.Shutdown` in their own goroutines (matching `cmd/monitor`'s wiring
exactly) and returns a channel that closes once both exit.

Seven tests changed from `detector.Run(ctx)` + `Submit*` to building a
`*Router` over real channels and sending on them directly; see
[02-tests.md](02-tests.md) for the exact substitution pattern.
`TestDetector_ContextCancellationClosesCompleted` was renamed to
`TestDetector_ShutdownClosesCompleted` and now calls `detector.Shutdown(ctx)`
directly, with no `Router` (it submits no events). `waitForDetectorExit`'s
timeout message was updated from `"detector.Run() did not exit in time"` to
`"detector pipeline (router + shutdown) did not exit in time"` — the
function itself is otherwise unchanged and still used by every migrated
test.

## `internal/output/json_writer_test.go` — migrate one test

`TestBuildRecordOnCompletedSessionWhileCollectorsStillWrite` (from the C2
fix) lives in a different package and can only use `session`'s exported
surface. Migrated using `session.NewRouter` and `Detector.Shutdown` directly
— both already exported — with the same channel-capacity convention as the
`internal/session` migration. Its own doc comment (explaining that it does
*not* reproduce the C2 race and is kept for different reasons — see the C2
fix's docs) is unchanged; only its event-delivery mechanism moved.

## Not changed

`Router`, `Router.Run`, `router_test.go`, every `handle*` method on
`Detector`, `HandleProcess`, `RouteToSession`, session/output/BPF code, and
every test assertion in all nine affected tests (eight migrated, one new).
