# 6. Results

## Goals vs. outcome

| # | Goal | Outcome |
|---|---|---|
| 1 | Each collector's drops counted | **met** — `DroppedEvents()` on all five, pinned by five new tests |
| 2 | Reported at shutdown | **met** — `cmd/monitor` logs each nonzero collector's drop count, matching H2/H4's report shape |
| 3 | Proven against a real drop, not a synthetic call | **met** — every test drives a genuine BPF-sourced event; the `ProcessCollector` deadlock was independently reproduced and re-confirmed closed, not just fixed and trusted |
| 4 | Nothing else changes | **met** — diff limited to `dropCount`/`DroppedEvents` per collector and `cmd/monitor`'s report block; full `-race`/root suites green, repeated |

## What the measurement shows

Before this fix, all five collectors' `Run` goroutines silently discarded
events under backpressure with no trace anywhere — a test filling
`fc.Events` to capacity and then triggering a real `openat()` had no way to
distinguish "the event was dropped" from "the event was never generated in
the first place." After:

```go
if got := fc.DroppedEvents(); got != 0 {
    t.Fatalf("DroppedEvents() = %d before any drop, want 0", got)
}
// ... fill Events to capacity, trigger a real openat() ...
if fc.DroppedEvents() > 0 {
    return // drop observed and counted
}
```

```
=== RUN   TestFileCollectorCountsDroppedEvents
--- PASS: TestFileCollectorCountsDroppedEvents (0.53s)
```

Repeated per-collector, with the appropriate real BPF event
(fork/openat/syscall/TCP-connect/TCP-write) for each. Every drop the audit
describes as invisible is now observable and distinguishable from "no event
occurred."

## Test results

| Package | Tests added/changed | Result |
|---|---|---|
| `internal/collector` | 5 new (`TestProcessCollectorCountsDroppedEvents`, `TestFileCollectorCountsDroppedEvents`, `TestSyscallCollectorCountsDroppedEvents`, `TestTcpCollectorCountsDroppedEvents`, `TestBytesCollectorCountsDroppedEvents`) | all 5 pass; repeated 3x back-to-back, clean each time |

Red → green: **5 genuine reds**, one per collector, all compile-level
(new `DroppedEvents` symbol referenced before it existed) — the same shape
as every other "new counter API" red in this fix series (H2's
`InsertFailures`, H4's `DroppedRoutesForUnknownPID`).

**Plus one test-bug discovered and fixed mid-task**: the first version of
`TestProcessCollectorCountsDroppedEvents` deadlocked under real concurrent
load. Reproduced deterministically (30s timeout, 3,000 concurrent
`/bin/true` spawns, exit code 124 — never completed) and re-confirmed
closed under the identical load (0.71s pass) after the rewrite. See
[04-how-it-was-done.md](04-how-it-was-done.md).

## Whole-repository verification

```
$ go build ./...
BUILD OK
$ go vet ./...
(clean)
$ go test -race ./... -count=1
ok  	.../cmd/dataset/exporter	1.011s
ok  	.../cmd/dataset/labeler	1.019s
ok  	.../cmd/dataset/validator	1.008s
ok  	.../cmd/monitor	1.016s
ok  	.../internal/collector	1.013s
ok  	.../internal/dataset	1.010s
ok  	.../internal/features	1.015s
ok  	.../internal/output	1.093s
ok  	.../internal/session	1.762s
$ sudo -n /usr/bin/go test ./... -count=1
(same 9 packages, all ok — internal/collector 4.3s)
$ for i in 1 2 3; do sudo -n /usr/bin/go test ./internal/collector/... -count=1; done
ok .../internal/collector 5.096s
ok .../internal/collector 5.179s
ok .../internal/collector 5.241s
```

Raw: [`root-suite.txt`](evidence/root-suite.txt),
[`race-suite.txt`](evidence/race-suite.txt).

## Real-binary confirmation

```
$ sudo -n /usr/bin/go run ./cmd/monitor -dry-run
  All probes loaded successfully.
```

Unchanged from prior fixes — this change touches no BPF attachment code.
Raw: [`dry-run-confirmation.txt`](evidence/dry-run-confirmation.txt).

## Diff size

| File | Change |
|---|---|
| `internal/collector/process_collector.go` | +`sync/atomic` import, +`dropCount` field, +1 line at drop site, +`DroppedEvents` accessor |
| `internal/collector/file_collector.go` | same shape |
| `internal/collector/syscall_collector.go` | same shape |
| `internal/collector/tcp_collector.go` | same shape |
| `internal/collector/bytes_collector.go` | same shape |
| `cmd/monitor/main.go` | +21-line shutdown report loop |
| `internal/collector/process_collector_test.go` | +1 test (~85 lines, including a deadlock discovered and closed mid-task) |
| `internal/collector/file_collector_test.go` | +1 test (~75 lines) |
| `internal/collector/syscall_collector_test.go` | new file, 1 test (~78 lines) |
| `internal/collector/tcp_collector_test.go` | new file, 1 test (~99 lines) |
| `internal/collector/bytes_collector_test.go` | new file, 1 test (~110 lines) |

No change to any BPF `.bpf.c` source, any `Run` loop's control flow beyond
the one added atomic increment per collector, or any other package.

## Status of AUDIT.md's High findings

| Finding | Status |
|---|---|
| H1 — `d.timers` leak | fixed, side effect of C3 |
| H2 — `pending_opens` leak / uncounted insert failures | fixed |
| H3 — dead `Detector.Run()`/`Submit*` machinery | fixed |
| H4 — router priority pattern / silent unknown-PID drops | fixed |
| H5 — silent, uncounted channel drops under backpressure | **fixed (this task)** — all five collectors counted and reported; underlying backpressure itself intentionally not eliminated (see [01-goals.md](01-goals.md) and [05-why-this-approach.md](05-why-this-approach.md)) |
| H6–H7 | open — see [07-findings-not-fixed.md](07-findings-not-fixed.md) |
