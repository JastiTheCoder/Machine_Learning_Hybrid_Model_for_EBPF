# 6. Results

## Goals vs. outcome

| # | Goal | Outcome |
|---|---|---|
| 1 | No unsynchronised reads of session state | **met** — 10 data races → 0 |
| 2 | Internally consistent record | **met** — every field read under one `s.mu` acquisition |
| 3 | Record does not alias live session state | **met** — `maps.Clone`, pinned by the independence test |
| 4 | Mutex stays private | **met** — `mu` still unexported; access is via a method |
| 5 | Proven with the race detector | **met** — slices 2 and 4 |
| 6 | Nothing else changes | **met** — `-race` and root suites green, 9 packages |

## The measurement that matters

`TestBuildRecordIsSafeWhileSessionIsStillBeingWrittenTo`, under `go test -race`:

**Before**

```
DATA RACE reports: 10
    testing.go:1712: race detected during execution of test
FAIL	github.com/aniruddha/npm-ebpf-monitor/internal/output	0.071s
```

including the crash vector itself:

```
Write at 0x00c0000c58c0 by goroutine 9:
  runtime.mapassign_faststr()
  session.(*Session).AddSyscall()      session.go:97

Previous read at 0x00c0000c58c0 by goroutine 17:
  runtime.mapaccess1_faststr()
  output.buildSyscallFeatures()        json_writer.go:255
  output.BuildRecord()                 json_writer.go:136
```

**After**

```
--- PASS: TestBuildRecordIsSafeWhileSessionIsStillBeingWrittenTo (0.05s)
ok  	github.com/aniruddha/npm-ebpf-monitor/internal/output	1.058s
```

`mapassign_faststr` racing `mapaccess1_faststr` on one address is exactly what
the Go runtime aborts the process for. Removing it removes the crash.

## Test results

| Package | Tests added | Result |
|---|---|---|
| `internal/session` | 3 functions | all pass under `-race` |
| `internal/output` | 2 functions | all pass under `-race` |

Red → green: **2 genuine reds** (slices 1 and 2), **1 guard** (slice 4), and
**1 seam that could not drive a red** (slice 3, documented).

## Whole-repository verification

```
$ go build ./...
BUILD OK

$ go test -race ./... -count=1
ok  .../cmd/dataset/exporter   1.013s
ok  .../cmd/dataset/labeler    1.017s
ok  .../cmd/dataset/validator  1.015s
ok  .../cmd/monitor            1.018s
ok  .../internal/collector     1.015s
ok  .../internal/dataset       1.014s
ok  .../internal/features      1.014s
ok  .../internal/output        1.064s
ok  .../internal/session       1.360s

$ sudo -n /usr/bin/go test ./... -count=1
   (same 9 packages, all ok)
```

`go vet ./...` clean; `gofmt` clean on both changed files (the three files
`gofmt -l` still reports — `detector_test.go`, `validator_test.go`, `writer.go`
— were already unformatted before this work and were not touched).

## Diff size

| File | Change |
|---|---|
| `internal/session/session.go` | +`Snapshot` type, +`Snapshot()` method, +`maps` import (~70 lines with comments) |
| `internal/output/json_writer.go` | `BuildRecord` body rewired; `sessionTimestamp` → `snapshotTimestamp` |
| `internal/session/session_test.go` | +3 tests, +1 helper |
| `internal/output/json_writer_test.go` | +2 tests, +2 helpers |

No BPF, no schema, no collector, no monitor changes.

## Status of the audit's Critical findings

| Finding | Status |
|---|---|
| C1 — `write_processes`/`read_processes` broken | fixed ([docs](../fix-c1-open-flags/)) |
| C2 — unlocked concurrent read in `BuildRecord` | **fixed** (this task) |
| C3 — session can be completed twice | **open** — next |
| C4 — malicious fixtures exported as benign | fixed ([docs](../fix-c4-ground-truth-labels/)) |

## What this unblocks

Capturing at scale. C2 was the failure that would have bitten hardest during a
long corpus run: the more sessions in flight and the more collector traffic, the
likelier the crash, and it takes every in-flight session with it.
