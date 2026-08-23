# 6. Results

## Goals vs. outcome

| # | Goal | Outcome |
|---|---|---|
| 1 | False doc claim corrected | **met** — `context/architecture.md:317` rewritten |
| 2 | Drop counted | **met** — `DroppedRoutesForUnknownPID()`, pinned by both tests |
| 3 | Drop logged in verbose mode | **met** — asserted directly in the new unit test |
| 4 | Reported at shutdown | **met** — `cmd/monitor` logs a nonzero count, matching the H2/silent-write-failures shape |
| 5 | Nothing else changes | **met** — `router.go` untouched; full `-race`/root suites green |

## The measurement that matters

`TestRouter_UnknownPID`, extended — three events (syscall, file, TCP) for a
PID with no registered session, routed through a **real `Router`**:

**Before:** the events vanished with no trace anywhere — the test only
checked that the target session's counts stayed at zero and that the unknown
PID never got attached, which is consistent with either "correctly ignored"
or "silently and permanently lost." Nothing distinguished the two.

**After:**

```go
if got := detector.DroppedRoutesForUnknownPID(); got != 3 {
    t.Fatalf("DroppedRoutesForUnknownPID() = %d, want 3", got)
}
```

```
--- PASS: TestRouter_UnknownPID (0.00s)
```

Three drops, three counted — the exact scenario the audit describes, now
observable rather than indistinguishable from correct behavior.

## Test results

| Package | Tests changed | Result |
|---|---|---|
| `internal/session` | 1 new (`TestRouteToSessionCountsAndLogsDropsForUnknownPID`), 1 extended (`TestRouter_UnknownPID`) | both pass, 5/5 repeat runs clean |

Red → green: **1 genuine red** (compile-level, new API), both tests passing
together once the accessor and counting logic existed.

## Whole-repository verification

```
$ go build ./...
BUILD OK

$ go vet ./...
(clean)

$ go test -race ./internal/session/... -v -count=1
   28 tests, all pass

$ for i in 1 2 3 4 5; do go test -race ./internal/session/... -count=1; done
ok  .../internal/session  (x5, all ok)

$ go test -race ./... -count=1
ok  .../cmd/dataset/exporter   1.015s
ok  .../cmd/dataset/labeler    1.017s
ok  .../cmd/dataset/validator  1.013s
ok  .../cmd/monitor            1.031s
ok  .../internal/collector     1.026s
ok  .../internal/dataset       1.027s
ok  .../internal/features      1.026s
ok  .../internal/output        1.087s
ok  .../internal/session       1.758s

$ sudo -n /usr/bin/go test ./... -count=1
   (same 9 packages, all ok)
```

Raw: [`repeat-runs-clean.txt`](evidence/repeat-runs-clean.txt),
[`race-suite.txt`](evidence/race-suite.txt),
[`root-suite.txt`](evidence/root-suite.txt).

## Real-binary confirmation

```
$ sudo -n /usr/bin/go run ./cmd/monitor -dry-run
  All probes loaded successfully.
```

Unchanged from prior fixes — this change touches no BPF or collector code.
Raw: [`dry-run-confirmation.txt`](evidence/dry-run-confirmation.txt).

## Diff size

| File | Change |
|---|---|
| `internal/session/detector.go` | +`routeDropCount uint64` field, +2 lines at the drop site, +`DroppedRoutesForUnknownPID` accessor (~15 lines with comments) |
| `cmd/monitor/main.go` | +4-line shutdown report |
| `internal/session/detector_test.go` | +1 test (~55 lines) |
| `internal/session/router_test.go` | +1 assertion (4 lines) |
| `context/architecture.md` | 1 paragraph rewritten |

No change to `router.go`, any `handle*` method, session, output, or BPF code.

## Status of the audit's High findings

| Finding | Status |
|---|---|
| H1 — `d.timers` leak | fixed, side effect of C3 |
| H2 — `pending_opens` leak / uncounted insert failures | fixed |
| H3 — dead `Detector.Run()`/`Submit*` machinery | fixed |
| H4 — router priority pattern / silent unknown-PID drops | **fixed** (this task) — doc corrected, drop counted and logged; underlying race intentionally not eliminated (see [01-goals.md](01-goals.md)) |
| H5–H7 | open — see [07-findings-not-fixed.md](07-findings-not-fixed.md) |
