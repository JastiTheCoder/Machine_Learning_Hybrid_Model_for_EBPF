# 4. How it was done

## Step 0 — verify the audit's claim, don't just believe it

Grepped the whole repository for `SubmitProcess`, `SubmitSyscall`,
`SubmitFile`, `SubmitTCP`, and `detector.Run(ctx)`. Confirmed: the four
`Submit*` methods had zero callers outside `internal/session/detector_test.go`
and (one test) `internal/output/json_writer_test.go`; `detector.Run(ctx)` had
exactly one caller, `cmd/monitor/main.go`. Raw:
[`evidence/pre-removal-caller-grep.txt`](evidence/pre-removal-caller-grep.txt).

## Step 0b — read `Run()` and `runOutputWorker` together before touching anything

This is the step that changed the shape of the fix. `Run()`'s body is:

```go
func (d *Detector) Run(ctx context.Context) {
	defer d.closeCompletedSessions()
	for { ... }
}
```

and `cmd/monitor/main.go`'s output worker does `for completed := range
detector.Completed()`. A `for range` over a channel only terminates when the
channel closes. Deleting `Run()` outright, with nothing calling
`closeCompletedSessions()` in its place, would have left that goroutine
blocked forever past `cancel()` — breaking `cmd/monitor`'s shutdown, not
fixing a coverage gap. This was caught by reading, not by a failing test,
which is exactly the discipline this project's `AUDIT.md` process asks for
before writing any code.

## Step 0c — confirm the fix shape and seams

Decided and confirmed before any test was written: remove the dead
`Submit*`/channel machinery entirely; replace `Run`'s one real job with a
two-line `Shutdown` method; migrate every affected test onto a live `Router`,
matching `router_test.go`'s existing idiom rather than inventing a second
one.

## Step 1 — change `detector.go`, fix the one call site

Removed the four channel fields, `Run`, and the four `Submit*` methods; added
`Shutdown`. `cmd/monitor/main.go`'s single call site changed from
`detector.Run(ctx)` to `detector.Shutdown(ctx)`.

```
$ go build ./...
cmd/monitor/main.go:145:47: detector.Run undefined (type *session.Detector has no field or method Run)
```

Expected — this is the compiler proving the call site needed updating, not a
test red. Fixed the one line; build succeeded.

## Step 2 — migrate the tests, package by package

`go vet ./...` pointed at exactly the two files needing migration:

```
vet: internal/session/detector_test.go:35:12: detector.Run undefined
vet: internal/output/json_writer_test.go:536:12: detector.Run undefined
```

**`internal/session/detector_test.go`**: added `startDetectorPipeline`, then
migrated all eight affected tests one at a time, running the package's tests
after each to catch a transcription mistake immediately rather than at the
end. Each migration was mechanical (see [03-what-was-done.md](03-what-was-done.md))
and none required touching an assertion.

**`internal/output/json_writer_test.go`**: `TestBuildRecordOnCompletedSessionWhileCollectorsStillWrite`
migrated the same way, using `session.NewRouter` and `Detector.Shutdown`
since this test lives outside the `session` package and can only use its
exported surface — which, notably, is sufficient: nothing internal to
`session` was needed to drive this test correctly, confirming `Router` and
`Shutdown` are a complete, exported production interface on their own.

## Step 3 — verify each migrated package, then the whole repository

```
$ go build ./...                                          BUILD OK
$ go vet ./...                                             clean
$ go test -race ./internal/session/... -v -count=1        all pass (27 tests)
$ go test -race ./internal/output/... -v -count=1          all pass (13 tests)
```

Raw: [`migrated-tests-green.txt`](evidence/migrated-tests-green.txt).

Repeated five times across both packages to rule out new flakiness from the
changed concurrency shape (a channel handoff to a separate `Router` goroutine
replacing a direct queue-push drained by a different loop):

```
$ for i in 1 2 3 4 5; do go test -race ./internal/session/... ./internal/output/... -count=1; done
ok  .../internal/session  (x5, all ok)
ok  .../internal/output   (x5, all ok)
```

Raw: [`repeat-runs-clean.txt`](evidence/repeat-runs-clean.txt).

Whole repository, both suites:

```
$ go test -race ./... -count=1                             all ok (9 packages)
$ sudo -n /usr/bin/go test ./... -count=1                   all ok (9 packages)
```

Raw: [`race-suite.txt`](evidence/race-suite.txt),
[`root-suite.txt`](evidence/root-suite.txt).

## Step 4 — confirm the real binary still starts

```
$ sudo -n /usr/bin/go run ./cmd/monitor -dry-run
  ✓ ProcessTracer      → tracepoint/syscalls/sys_enter_execve, sched_process_fork, sched_process_exit
  ✓ SyscallTracer      → tracepoint/raw_syscalls/sys_enter
  ✓ FileMonitor        → tracepoint/syscalls/sys_enter_openat, sys_exit_openat, sched_process_exit
  ✓ TCPMonitor         → tracepoint/sock/inet_sock_set_state
  ✓ BytesCollector     → kprobe/tcp_sendmsg, kretprobe/tcp_recvmsg
  All probes loaded successfully.
```

`runDryRun` never touches `Detector.Run`/`Shutdown` (it loads collectors and
exits before starting any long-lived goroutine), so this mainly confirms the
rest of `main.go` still compiles and runs correctly around the changed call
site. Raw: [`dry-run-confirmation.txt`](evidence/dry-run-confirmation.txt).

A full foreground capture with a graceful `SIGINT` shutdown — which would
directly exercise `Detector.Shutdown` closing `Completed()` in the real
binary — was not performed, for the same environment reason recorded in
[`../fix-pending-opens-leak/06-results.md`](../fix-pending-opens-leak/06-results.md):
this sandboxed session's non-root shell cannot signal a root-owned `go
run`-launched process. `TestDetector_ShutdownClosesCompleted` plus
`TestRunOutputWorkerReportsWriteOutcomes`'s "no sessions at all" case
(which already depends on a closed input channel to terminate its own `for
range`) together cover the exact chain of behavior the real shutdown path
depends on.
