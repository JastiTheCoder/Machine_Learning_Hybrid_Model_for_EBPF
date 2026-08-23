# 6. Results

## Goals vs. outcome

| # | Goal | Outcome |
|---|---|---|
| 1 | Dead machinery removed | **met** — `Run`, `SubmitProcess/Syscall/File/TCP`, and their 4 channel fields deleted; grep confirms nothing remains |
| 2 | `Completed()` still closes on shutdown | **met** — `Detector.Shutdown`, pinned by `TestDetector_ShutdownClosesCompleted` |
| 3 | All affected tests moved onto the real path | **met** — 8 tests migrated onto a live `Router`, identical assertions |
| 4 | Nothing else changes | **met** — full `-race`/root suites green; 5 repeated runs, zero flakes |

## The measurement that matters

Not a red→green defect count — this task closes a coverage/dead-code gap,
not a logic bug. The measurement is **what path is now exercised**:

| | Before | After |
|---|---|---|
| `TestDetector_NpmInstallLifecycle` and 6 siblings | `Submit*` → `Detector`'s own private channels → `Run()`'s loop → `HandleProcess`/`handleSyscall`/`handleFile`/`handleTCP` | Real channels → `Router.Run` → `HandleProcess`/`RouteToSession` — **the same calls `cmd/monitor/main.go` makes** |
| `TestBuildRecordOnCompletedSessionWhileCollectorsStillWrite` | same dead path, different package | same real path, using only `session`'s exported API |
| Production `Detector.Run()` goroutine | ran forever, did nothing but wait for `ctx.Done()` | doesn't exist; replaced by `Shutdown`, which does the one thing that goroutine's existence actually accomplished |

All nine tests (eight migrated, one new) pass with the assertions unchanged
— proof that the migration is behavior-preserving, not proof of a fixed
defect, because there was no defect in `HandleProcess`/`RouteToSession`
themselves to begin with. The defect was that most of this package's own
test suite was not proving what it appeared to prove.

## Test results

| Package | Tests changed | Result |
|---|---|---|
| `internal/session` | 7 migrated, 1 renamed+migrated, 1 new helper | all pass, 5/5 repeat runs clean |
| `internal/output` | 1 migrated | all pass, 5/5 repeat runs clean |

## Whole-repository verification

```
$ go build ./...
BUILD OK

$ go vet ./...
(clean)

$ go test -race ./... -count=1
ok  .../cmd/dataset/exporter   1.013s
ok  .../cmd/dataset/labeler    1.022s
ok  .../cmd/dataset/validator  1.010s
ok  .../cmd/monitor            1.022s
ok  .../internal/collector     1.012s
ok  .../internal/dataset       1.012s
ok  .../internal/features      1.013s
ok  .../internal/output        1.075s
ok  .../internal/session       1.695s

$ sudo -n /usr/bin/go test ./... -count=1
   (same 9 packages, all ok)
```

Raw: [`race-suite.txt`](evidence/race-suite.txt),
[`root-suite.txt`](evidence/root-suite.txt).

## Real-binary confirmation

```
$ sudo -n /usr/bin/go run ./cmd/monitor -dry-run
  All probes loaded successfully.
```

A full foreground capture with a graceful `SIGINT` shutdown was not
performed — see [04-how-it-was-done.md](04-how-it-was-done.md) for the
environment limitation and what covers the same ground instead. Raw:
[`dry-run-confirmation.txt`](evidence/dry-run-confirmation.txt).

## Diff size

| File | Change |
|---|---|
| `internal/session/detector.go` | −4 channel fields, −`Run` (~25 lines), −4 `Submit*` methods (~40 lines), +`Shutdown` (~20 lines with comments) |
| `cmd/monitor/main.go` | 1 line: `detector.Run(ctx)` → `detector.Shutdown(ctx)` |
| `internal/session/detector_test.go` | +1 helper (`startDetectorPipeline`), 8 tests migrated (1 renamed) |
| `internal/output/json_writer_test.go` | 1 test migrated |

No change to `Router`, `router_test.go`, any `handle*` method, session,
output, or BPF code.

## Status of the audit's High findings

| Finding | Status |
|---|---|
| H1 — `d.timers` leak | fixed, side effect of C3 |
| H2 — `pending_opens` leak / uncounted insert failures | fixed |
| H3 — dead `Detector.Run()`/`Submit*` machinery | **fixed** (this task) |
| H4–H7 | open — see [07-findings-not-fixed.md](07-findings-not-fixed.md) |
