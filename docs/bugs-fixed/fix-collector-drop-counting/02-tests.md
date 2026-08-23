# 2. Tests

Five structurally identical vertical slices, one per collector, taken in
this order: `ProcessCollector` → `FileCollector` → `SyscallCollector` →
`TcpCollector` → `BytesCollector`. `ProcessCollector` went first because it
already had a test file and BPF-struct precedent to build from; the other
four follow the same shape once established.

## Seams — agreed before any test written

| Seam | Outcome |
|---|---|
| Each collector's own `DroppedEvents()` contract, driven by a real BPF event through that collector's real `Run` goroutine | ✅ one new test per collector |
| Each collector's `Run` loop / decode logic | not touched — out of scope |
| `cmd/monitor`'s shutdown report itself | not unit-tested — see [07-findings-not-fixed.md](07-findings-not-fixed.md), same gap already accepted for H2/H4's equivalent lines |

## Slice 1 — `TestProcessCollectorCountsDroppedEvents`

Fills `pc.Events` toward capacity, seeds this process as tracked, forks a
real `/bin/sleep` child (a real FORK event), and asserts `DroppedEvents()`
rises. **Result: achieved, but only after a second round-trip through
red/green — see below.**

Red (against pre-fix `process_collector.go`, no `DroppedEvents` method at
all):

```
internal/collector/process_collector_test.go:315:15: pc.DroppedEvents undefined (type *ProcessCollector has no field or method DroppedEvents)
internal/collector/process_collector_test.go:340:9: pc.DroppedEvents undefined (type *ProcessCollector has no field or method DroppedEvents)
FAIL	github.com/aniruddha/npm-ebpf-monitor/internal/collector [build failed]
```

Green, in isolation:

```
=== RUN   TestProcessCollectorCountsDroppedEvents
--- PASS: TestProcessCollectorCountsDroppedEvents (0.82s)
PASS
```

Raw: [`slice1-process-red.txt`](evidence/slice1-process-red.txt),
[`slice1-process-green.txt`](evidence/slice1-process-green.txt),
[`slice1-full-package-green.txt`](evidence/slice1-full-package-green.txt)
(whole `internal/collector` package, confirming nothing else regressed).

**This "green" was not actually done.** The first version of this test used
a plain blocking fill loop (`pc.Events <- ProcessEvent{}`, no `select`) and
asserted an absolute `DroppedEvents() == 0` baseline before the fill. Both
assumptions are false for `ProcessCollector` specifically, because its BPF
program emits execve events for the whole machine, not just tracked PIDs
(see [04-how-it-was-done.md](04-how-it-was-done.md) for the full account).
Running the *entire* repository's test suite — not just this test in
isolation — surfaced a real deadlock: `go test ./...`'s own concurrent
subprocess-spawning across other packages generated enough ambient exec
traffic that the blocking fill loop hung permanently, timing out the whole
suite at 10 minutes. The test was rewritten to use a non-blocking fill and a
relative (`after > before`) assertion — the final version quoted in
[03-what-was-done.md](03-what-was-done.md) — and the deadlock was then
independently reproduced and closed under a controlled load (see below),
not just fixed and trusted.

## Slice 2 — `TestFileCollectorCountsDroppedEvents`

Fills `fc.Events` to capacity with a plain blocking loop (safe here: unlike
`ProcessCollector`, `file_monitor.bpf.c` gates emission on `is_tracked()`,
so no ambient traffic can be pushed into this channel by an untracked
process), seeds this process as tracked, opens a real file via
`syscall.Open`, and asserts `DroppedEvents()` rises above an absolute-zero
baseline.

Red:

```
internal/collector/file_collector_test.go:401:15: fc.DroppedEvents undefined (type *FileCollector has no field or method DroppedEvents)
internal/collector/file_collector_test.go:426:9: fc.DroppedEvents undefined (type *FileCollector has no field or method DroppedEvents)
FAIL	github.com/aniruddha/npm-ebpf-monitor/internal/collector [build failed]
```

Green:

```
=== RUN   TestFileCollectorCountsDroppedEvents
--- PASS: TestFileCollectorCountsDroppedEvents (0.53s)
```

Raw: [`slice2-file-red.txt`](evidence/slice2-file-red.txt),
[`slice2-file-green.txt`](evidence/slice2-file-green.txt).

## Slice 3 — `TestSyscallCollectorCountsDroppedEvents`

New test file (`syscall_collector.go` had no existing `_test.go`). Same
absolute-zero-baseline, blocking-fill shape as slice 2 — safe here for the
same reason: `syscall_tracer.bpf.c` gates on `is_tracked()`. Seeds this
process as tracked; no synthetic event needed, since the Go runtime itself
makes a continuous stream of real syscalls (GC, scheduler, timers) that
`raw_syscalls/sys_enter` reports once this PID is tracked.

Red:

```
internal/collector/syscall_collector_test.go:49:15: sc.DroppedEvents undefined (type *SyscallCollector has no field or method DroppedEvents)
internal/collector/syscall_collector_test.go:70:9: sc.DroppedEvents undefined (type *SyscallCollector has no field or method DroppedEvents)
FAIL	github.com/aniruddha/npm-ebpf-monitor/internal/collector [build failed]
```

Green:

```
=== RUN   TestSyscallCollectorCountsDroppedEvents
--- PASS: TestSyscallCollectorCountsDroppedEvents (0.40s)
```

Raw: [`slice3-syscall-red.txt`](evidence/slice3-syscall-red.txt),
[`slice3-syscall-green.txt`](evidence/slice3-syscall-green.txt).

## Slice 4 — `TestTcpCollectorCountsDroppedEvents`

New test file. Same shape again — `tcp_monitor.bpf.c` gates on
`is_tracked()` too. Drives a real loopback `net.Listen`/`net.Dial`
connection from the tracked process to generate real TCP state-transition
events through `tcp_monitor.bpf.c`'s own `sock_to_pid` process-context
registration.

Red:

```
internal/collector/tcp_collector_test.go:50:15: tc.DroppedEvents undefined (type *TcpCollector has no field or method DroppedEvents)
internal/collector/tcp_collector_test.go:93:9: tc.DroppedEvents undefined (type *TcpCollector has no field or method DroppedEvents)
FAIL	github.com/aniruddha/npm-ebpf-monitor/internal/collector [build failed]
```

Green:

```
=== RUN   TestTcpCollectorCountsDroppedEvents
--- PASS: TestTcpCollectorCountsDroppedEvents (0.36s)
```

Raw: [`slice4-tcp-red.txt`](evidence/slice4-tcp-red.txt),
[`slice4-tcp-green.txt`](evidence/slice4-tcp-green.txt).

## Slice 5 — `TestBytesCollectorCountsDroppedEvents`

New test file. Same shape once more. Drives a real loopback TCP `Write()`
from the tracked process to trigger `kprobe/tcp_sendmsg` in that process's
own context.

Red:

```
internal/collector/bytes_collector_test.go:49:15: bc.DroppedEvents undefined (type *BytesCollector has no field or method DroppedEvents)
internal/collector/bytes_collector_test.go:101:9: bc.DroppedEvents undefined (type *BytesCollector has no field or method DroppedEvents)
FAIL	github.com/aniruddha/npm-ebpf-monitor/internal/collector [build failed]
```

Green:

```
=== RUN   TestBytesCollectorCountsDroppedEvents
--- PASS: TestBytesCollectorCountsDroppedEvents (0.44s)
```

Raw: [`slice5-bytes-red.txt`](evidence/slice5-bytes-red.txt),
[`slice5-bytes-green.txt`](evidence/slice5-bytes-green.txt).

## The deadlock: proved, not assumed

Because this task was explicitly asked to follow TDD "to the teeth," the
fixed `ProcessCollector` test's teeth were checked directly rather than
trusted: the original blocking-fill / absolute-zero-baseline version was
reconstructed in isolation and re-run under an artificial load of 3,000
concurrently-spawned `/bin/true` processes, bounded by a 30-second
`timeout`. It hung for the full 30 seconds and was killed (`timeout` exit
code 124) — a direct, reproducible confirmation that the deadlock is real,
not a one-off flake from the earlier full-suite run. The fixed
(non-blocking-fill, relative-assertion) version was then re-run under the
identical load and passed in 0.71s.

Broken version, timed out:

```
$ timeout 30s sudo -n /usr/bin/go test ./internal/collector/... -run TestProcessCollectorCountsDroppedEvents -v -count=1
=== RUN   TestProcessCollectorCountsDroppedEvents
[killed after 30s, exit code 124 — no PASS/FAIL line was ever reached]
```

Fixed version, same load:

```
=== RUN   TestProcessCollectorCountsDroppedEvents
--- PASS: TestProcessCollectorCountsDroppedEvents (0.71s)
PASS
ok  	github.com/aniruddha/npm-ebpf-monitor/internal/collector	0.715s
```

Raw:
[`slice1-process-deadlock-repro-broken-version-timeout.txt`](evidence/slice1-process-deadlock-repro-broken-version-timeout.txt),
[`slice1-process-fixed-under-concurrent-load-after.txt`](evidence/slice1-process-fixed-under-concurrent-load-after.txt),
[`slice1-process-teeth-check-under-load.txt`](evidence/slice1-process-teeth-check-under-load.txt)
(an earlier, lighter-load pass of the same check).

## Goal coverage

| Goal | Covered by | Achieved |
|---|---|---|
| 1 — each collector's drops counted | All five new tests | yes |
| 2 — shutdown report | `cmd/monitor/main.go` change, not itself unit-tested (see [07-findings-not-fixed.md](07-findings-not-fixed.md)) | yes (code), partial (test coverage) |
| 3 — proven against a real drop, not a synthetic call | Every test drives at least one real BPF-sourced event; `ProcessCollector`'s deadlock was independently reproduced and re-checked closed, not just fixed and trusted | yes |
| 4 — nothing else changes | Diff limited to `dropCount`/`DroppedEvents` per collector plus `cmd/monitor`'s report block; full `-race`/root suites green (repeated 3x for the collector package specifically) | yes |
