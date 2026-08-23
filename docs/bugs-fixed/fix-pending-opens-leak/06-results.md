# 6. Results

## Goals vs. outcome

| # | Goal | Outcome |
|---|---|---|
| 1 | Insert failures counted | **met** — `TestFileMonitorCountsFailedPendingOpensInserts`, red → green |
| 2 | No entry outlives its thread | **met for the reproducible case; honestly partial overall** — see below |
| 3 | Proven under real load/run | **met** — both tests root-gated, real BPF load/attach, real syscalls |
| 4 | Nothing else changes | **met** — full `-race`/root suites green; 3 untouched `.o`/`.go` pairs byte-identical to `HEAD` |

Goal 2 in full: the audit's specific scenario (SIGKILL during an
interruptible `openat()`) turned out to already self-heal on this kernel via
the pre-existing `sys_exit_openat` path — an empirical, audit-correcting
finding, not an assumption. The new `sched_process_exit` hook is proven
independently sufficient for that same scenario (isolation test), and the
underlying leak is proven real in principle (both-paths-disabled test), but
its value as a *fix* rests on an unreproduced scenario (an uninterruptible/
D-state block) rather than a demonstrated one. Stated plainly rather than
glossed over — see [02-tests.md](02-tests.md) for the full isolation matrix.

## The measurement that matters

`TestFileMonitorCountsFailedPendingOpensInserts`, 4096 synthetic entries
forcing one real tracked `openat()`'s insert to fail:

**Before**

```
file_collector_test.go:340: file_monitor_stats[pending_opens insert failed]
    did not increase (before=0, after=0) after a real openat() with
    pending_opens full; the failed insert went uncounted (AUDIT.md H2)
--- FAIL: TestFileMonitorCountsFailedPendingOpensInserts
```

**After**

```
--- PASS: TestFileMonitorCountsFailedPendingOpensInserts (0.48s)
```

Every insert failure into a full `pending_opens` — previously invisible —
is now a `uint64` one `Lookup` call away, and `cmd/monitor` reports it at
shutdown.

## The isolation matrix that matters just as much

| Cleanup path(s) enabled | `TestFileCollectorClearsPendingOpensEntryWhenKilledMidOpenat` |
|---|---|
| Both (the shipped fix) | **PASS** |
| `sched_process_exit` hook only | **PASS** |
| `sys_exit_openat`'s own deletes only | **PASS** |
| Neither | **FAIL** — genuine leak reproduced |

The bottom row is the proof that `pending_opens` can leak at all; the middle
two rows are the proof that either fix independently closes it; the top row
is what ships.

## Test results

| Package | Tests added | Result |
|---|---|---|
| `internal/collector` | 2 functions, 1 helper, 1 fixture | all pass under root, 3/3 repeat runs clean |

Red → green: **1 genuine red** (the counter, slice 1). **1 seam that revealed
an audit-correcting finding rather than a straightforward red** (the leak,
slice 2) — investigated via a throwaway diagnostic and three isolation
rebuilds rather than accepted at face value.

## Whole-repository verification

```
$ go build ./...
BUILD OK

$ go test -race ./... -count=1
ok  .../cmd/dataset/exporter   1.014s
ok  .../cmd/dataset/labeler    1.018s
ok  .../cmd/dataset/validator  1.013s
ok  .../cmd/monitor            1.014s
ok  .../internal/collector     1.012s
ok  .../internal/dataset       1.014s
ok  .../internal/features      1.016s
ok  .../internal/output        1.070s
ok  .../internal/session       1.787s

$ sudo -n /usr/bin/go test ./... -count=1
   (same 9 packages, all ok)
```

`go vet ./...` clean. `gofmt -l` reports no new offenders in any file this
fix touched (`bytes_collector.go`/`collector.go` were already unformatted at
`HEAD`, confirmed by stashing this work and re-running `gofmt -l` against the
pre-existing tree).

Raw: [`race-suite.txt`](evidence/race-suite.txt),
[`root-suite.txt`](evidence/root-suite.txt).

## Real-binary confirmation

```
$ sudo -n /usr/bin/go run ./cmd/monitor -dry-run
  ✓ ProcessTracer      → tracepoint/syscalls/sys_enter_execve, sched_process_fork, sched_process_exit
  ✓ SyscallTracer      → tracepoint/raw_syscalls/sys_enter
  ✓ FileMonitor        → tracepoint/syscalls/sys_enter_openat, sys_exit_openat, sched_process_exit
  ✓ TCPMonitor         → tracepoint/sock/inet_sock_set_state
  Kernel: Linux version 7.1.9-arch1-2      BTF: supported        CO-RE: supported
  All probes loaded successfully.
```

Confirms the new third tracepoint attaches cleanly in the actual production
binary, not just in the test harness's own `NewFileCollector` calls. A full
foreground capture with a real `npm install` and a graceful shutdown was not
performed: this sandboxed session's non-root shell has no path to signal a
root-owned `go run`-launched process for a clean exit (`sudo -n kill` is
refused — only `/usr/bin/go` itself is passwordless per this machine's
sudoers rule). The dry run plus the root-gated unit suite (which loads and
runs the same `FileCollector` code the real binary uses) cover the actual
risk surface; noted here as an environment limitation rather than skipped
silently.

Raw: [`dry-run-attachment.txt`](evidence/dry-run-attachment.txt).

## Diff size

| File | Change |
|---|---|
| `bpf/file_monitor.bpf.c` | +`file_monitor_stats` map, +`count_stat` helper, insert-site check, +`sched_process_exit` tracepoint (~60 lines with comments) |
| `internal/collector/file_collector.go` | +3rd tracepoint link, +`PendingOpensInsertFailures` accessor |
| `internal/collector/file_collector_test.go` | +2 tests, +1 helper, +1 value struct |
| `internal/collector/testdata/block_in_openat.c` | new fixture |
| `cmd/monitor/main.go` | shutdown counter report, dry-run status string fix |
| `internal/collector/filemonitor_x86_bpfel.{o,go}` | regenerated (this program only) |

No change to `process_tracer.bpf.c`, `syscall_tracer.bpf.c`,
`tcp_monitor.bpf.c`, or any output schema.

## Status of the audit's High findings

| Finding | Status |
|---|---|
| H1 — `d.timers` leak | fixed, as a side effect of C3 ([docs](../fix-c3-double-completion/)) |
| H2 — `pending_opens` leak / uncounted insert failures | **fixed** (this task) — counting fully demonstrated; leak-cleanup partially demonstrated, honestly stated |
| H3–H7 | open — see [07-findings-not-fixed.md](07-findings-not-fixed.md) |
