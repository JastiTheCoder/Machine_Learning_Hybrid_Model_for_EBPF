# 4. How it was done

## Step 0 — verify the audit's claims against the actual code and doc

Read `context/architecture.md:317` and confirmed it states the exact false
guarantee H4 quotes. Read `Router.Run`'s `select` structure (`router.go`) and
confirmed the outer case only fires when a value is already buffered on
`procCh` at the instant `select` evaluates — Go's `select` with `default`
checks once, it does not wait or poll. Read `RouteToSession` (`detector.go`)
and confirmed `if session == nil { return }` is the sole, literal drop point,
with no counter, log, or retry anywhere in the function.

Grepped each of the five collectors to confirm the "five independent
ring-buffer-reading goroutines" claim: each `Collector.Run(ctx)` reads its
own `ringbuf.Reader` in its own goroutine, with no shared sequencing
primitive across collectors anywhere in the codebase.

## Step 0b — decide the fix shape before writing a test

Per the TDD skill's requirement, the seams and approach were settled first:
count and log the drop on the real `RouteToSession` path; correct the false
doc claim; do not attempt to eliminate the underlying race (see
[05-why-this-approach.md](05-why-this-approach.md) for the alternatives
considered and rejected).

## Step 1 — extend the existing seam first

`TestRouter_UnknownPID` already drove the exact scenario H4 describes
(events for an unregistered PID, through a real `Router`). Adding one
assertion to it — rather than writing a parallel test from scratch — was the
smaller, higher-fidelity choice: this test already proves the counter
increments through production's real dispatch path.

## Step 2 — write the new unit-level test with its negative check

`TestRouteToSessionCountsAndLogsDropsForUnknownPID` was written to include
the known-PID negative check from the start, not added after the fact — a
counter that increments unconditionally (ignoring whether a session was
actually found) would be a plausible, wrong first implementation, and the
negative check is what would catch it.

## Step 3 — red

```
$ go test ./internal/session/... -run 'TestRouteToSessionCountsAndLogsDropsForUnknownPID|TestRouter_UnknownPID' -v
internal/session/detector_test.go:820:21: detector.DroppedRoutesForUnknownPID undefined
internal/session/detector_test.go:832:21: detector.DroppedRoutesForUnknownPID undefined
internal/session/detector_test.go:855:21: detector.DroppedRoutesForUnknownPID undefined
internal/session/router_test.go:203:21: detector.DroppedRoutesForUnknownPID undefined
FAIL	github.com/aniruddha/npm-ebpf-monitor/internal/session [build failed]
```

A compile-level red, for the same reason as the C3 fix's `MarkCompleteOnce
undefined`: the accessor is genuinely new API, so there is no way to
red on wrong *behavior* before the symbol exists at all.

Raw: [`red.txt`](evidence/red.txt).

## Step 4 — implement

The diff in [03-what-was-done.md](03-what-was-done.md): the `routeDropCount`
field, the `atomic.AddUint64`/`d.logf` call at the drop site, the
`DroppedRoutesForUnknownPID` accessor, and the `cmd/monitor` shutdown line.

## Step 5 — green

```
$ go test ./internal/session/... -run 'TestRouteToSessionCountsAndLogsDropsForUnknownPID|TestRouter_UnknownPID' -v
--- PASS: TestRouteToSessionCountsAndLogsDropsForUnknownPID (0.00s)
--- PASS: TestRouter_UnknownPID (0.00s)
```

Raw: [`green.txt`](evidence/green.txt).

## Step 6 — correct the documentation

Rewrote `context/architecture.md:317`'s paragraph. This file lives outside
`npm-ebpf-monitor/` (in the top-level project's shared `context/` directory),
but H4 names this exact paragraph as its subject, so — unlike the same file's
unrelated `Detector.Run` staleness noted and deliberately left alone in
[`../fix-dead-detector-run/07-findings-not-fixed.md`](../fix-dead-detector-run/07-findings-not-fixed.md) —
correcting it here is squarely this task's scope, not a drive-by.

## Step 7 — verify the whole repository

```
$ go build ./...                                BUILD OK
$ go vet ./...                                  clean
$ go test -race ./internal/session/... -v       all pass (28 tests)
$ for i in 1 2 3 4 5; do go test -race ./internal/session/... -count=1; done
                                                 5/5 clean, zero flakes
$ go test -race ./... -count=1                  all ok (9 packages)
$ sudo -n /usr/bin/go test ./... -count=1       all ok (9 packages)
```

Raw: [`repeat-runs-clean.txt`](evidence/repeat-runs-clean.txt),
[`race-suite.txt`](evidence/race-suite.txt),
[`root-suite.txt`](evidence/root-suite.txt).

## Step 8 — confirm the real binary

```
$ sudo -n /usr/bin/go run ./cmd/monitor -dry-run
  All probes loaded successfully.
```

Unchanged from prior fixes' dry-run output — this change touches no BPF code
and no collector attachment, so the dry-run's only role here is confirming
`cmd/monitor/main.go` still compiles and runs correctly around the new
shutdown-reporting line. Raw:
[`dry-run-confirmation.txt`](evidence/dry-run-confirmation.txt).

A live reproduction of an actual cross-channel drop in the real binary
(forcing a syscall event to genuinely outrace its EXEC event under a real
`npm install`) was not attempted: the race is a physical timing race between
independent kernel ring-buffer reads, not something that can be reliably
forced from outside without instrumenting the collectors themselves, and
`TestRouter_UnknownPID`'s extension already proves the counting logic works
correctly once the race occurs, through the real dispatch path.
