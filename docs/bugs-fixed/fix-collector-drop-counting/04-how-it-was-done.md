# 4. How it was done

## eBPF/kernel-boundary note, up front

This fix touches **no BPF C source, no kernel-side program, and no map
layout** — the drop this closes happens entirely in Go userspace, at the
`select`/`default` boundary between a collector's ring-buffer reader
goroutine and its `Events` channel, after the kernel has already delivered
the event. There is therefore nothing here that needs verifier-level
validation; every test below is a real load/run against the actual compiled
BPF objects (`sudo -n /usr/bin/go test`, `os.Geteuid() != 0` skip guard,
`rlimit.RemoveMemlock()`), the same requirement every other collector test
in this package already carries, not a new environment constraint this fix
introduces.

## Step 0 — verify the audit's claim against actual code

Grepped all five `Run(ctx)` methods and confirmed each contains exactly the
`select { case c.Events <- evt: default: /* drop, no counter */ }` shape
H5 quotes, with nothing else — no counter increment, no log call — in the
`default` branch. Checked `docs/` for any doc that might already cover
this: none do (see [01-goals.md](01-goals.md) for the specific docs
checked and why they don't overlap).

## Step 1 — slice order and per-slice shape, decided before writing any test

Per the TDD skill, one vertical slice per collector, `ProcessCollector`
first (existing test file, existing BPF-struct-layout precedent to build
from), then the four collectors gated by `is_tracked()` in whatever order
they appear in the codebase (`file_monitor.bpf.c`, `syscall_tracer.bpf.c`,
`tcp_monitor.bpf.c`, then `bytes_collector.go`, which shares
`tcp_monitor.bpf.c`'s object but only attaches its `kprobe/tcp_sendmsg` and
`kretprobe/tcp_recvmsg` programs). Each slice: red (compile-level, new
`DroppedEvents` symbol referenced before it exists) → implement the
`dropCount`/`DroppedEvents` pair → green, before moving to the next slice.
No horizontal "add the field to all five, then write all five tests"
pass — each collector went red, then green, on its own, in its own commit
of work.

## Step 2 — slices 1 through 5, straightforward

For `ProcessCollector` (slice 1), `FileCollector` (slice 2),
`SyscallCollector` (slice 3), `TcpCollector` (slice 4), and `BytesCollector`
(slice 5): write the test referencing `<var>.DroppedEvents()`, confirm the
compile-level red (`<Type> has no field or method DroppedEvents`), add the
`sync/atomic` import + `dropCount` field + `atomic.AddUint64` at the drop
site + `DroppedEvents()` accessor, confirm green in isolation. Raw
red/green pairs for all five: [02-tests.md](02-tests.md).

## Step 3 — full-suite verification surfaces a real bug

Per this task's explicit instruction to follow TDD "to the teeth," the
whole repository's test suite was run — not just the five new tests in
isolation — as the actual acceptance bar, first `go test -race ./...`, then
`sudo -n /usr/bin/go test ./...` (backgrounded, since it exceeds the 120s
foreground timeout). The root run hit `panic: test timed out after 10m0s`,
with the goroutine dump showing `TestProcessCollectorCountsDroppedEvents`
blocked on a channel send for over 9 minutes.

**Root cause, confirmed by reading, not guessed:** `process_tracer.bpf.c`'s
`sys_enter_execve` tracepoint handler has no `is_tracked()` gate — it emits
an event for *every* execve() on the machine, because tracking a PID begins
at exec, so the check can't happen before the first event for that PID
exists. Confirmed by grepping for `is_tracked` in
`bpf/process_tracer.bpf.c` (absent from the exec handler) versus
`bpf/file_monitor.bpf.c`, `bpf/syscall_tracer.bpf.c`, and
`bpf/tcp_monitor.bpf.c` (present as a gate in each). The original test's fill
loop was a plain blocking send (`pc.Events <- ProcessEvent{}`, 1024 times,
no `select`/`default`) and its baseline assertion was `DroppedEvents() ==
0`. Under the full suite's own concurrent subprocess spawning (other
packages' tests fork real processes too), `Run()`'s goroutine was already
pushing real, unrelated exec events into the same `Events` channel the test
was filling — and since nothing in the test ever drains `Events`, once the
channel was genuinely full (real + synthetic combined), the test's blocking
send waited forever for a slot that would never open.

## Step 4 — fix the test, not the production code

This is a test bug, not a production bug: `ProcessCollector.Run` itself
behaves correctly (it does drop and count under backpressure, per the
`select`/`default` fix already applied in step 2) — only the *test's own
setup* could deadlock. Rewrote
`TestProcessCollectorCountsDroppedEvents` three ways:

1. Record `before := pc.DroppedEvents()` instead of asserting it starts at
   `0` — ambient exec traffic may have already produced drops before the
   test's own fill loop runs.
2. Replace the blocking fill loop with a non-blocking
   `select { case pc.Events <- ProcessEvent{}: default: }` loop, which can
   top the channel up toward capacity without ever being able to block,
   regardless of what `Run()`'s own goroutine is concurrently doing to the
   same channel.
3. Assert `DroppedEvents() > before` (relative movement) instead of `> 0`
   (absolute) at the end.

This is the same `before`/`after` relative-counter pattern already
established in the H2 fix's `TestFileMonitorCountsFailedPendingOpensInserts`
(there, for a BPF map counter that can't be reset between test runs against
a shared kernel resource; here, for a channel that real ambient system
activity can pre-populate).

## Step 5 — prove the deadlock is real and the fix closes it, don't just trust it

A test that merely "didn't hang this run" isn't proof for a race condition.
The original blocking-fill / absolute-baseline version was reconstructed in
a scratch copy and re-run under an artificial load of 3,000 concurrently
spawned `/bin/true` processes, bounded by a 30-second `timeout` (rather
than waiting out a possible 10-minute hang again): it never completed
within 30s (`timeout` exit code 124). The fixed version was then re-run
under the identical load and passed in 0.71s. Both runs, raw:
[`slice1-process-deadlock-repro-broken-version-timeout.txt`](evidence/slice1-process-deadlock-repro-broken-version-timeout.txt),
[`slice1-process-fixed-under-concurrent-load-after.txt`](evidence/slice1-process-fixed-under-concurrent-load-after.txt).
The scratch copy was discarded immediately after; the shipped test file is
the fixed version only.

## Step 6 — verify the whole repository, clean, multiple times

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
(same 9 packages, all ok, internal/collector 4.3s)
$ for i in 1 2 3; do sudo -n /usr/bin/go test ./internal/collector/... -count=1; done
ok  .../internal/collector 5.096s
ok  .../internal/collector 5.179s
ok  .../internal/collector 5.241s
```

Raw: [`root-suite.txt`](evidence/root-suite.txt),
[`race-suite.txt`](evidence/race-suite.txt).

## Step 7 — confirm the real binary

```
$ sudo -n /usr/bin/go run ./cmd/monitor -dry-run
  ✓ ProcessTracer      → tracepoint/syscalls/sys_enter_execve, sched_process_fork, sched_process_exit
  ✓ SyscallTracer      → tracepoint/raw_syscalls/sys_enter
  ✓ FileMonitor        → tracepoint/syscalls/sys_enter_openat, sys_exit_openat, sched_process_exit
  ✓ TCPMonitor         → tracepoint/sock/inet_sock_set_state
  ✓ BytesCollector     → kprobe/tcp_sendmsg, kretprobe/tcp_recvmsg
  Kernel: Linux version 7.1.9-arch1-2      BTF: supported        CO-RE: supported
  All probes loaded successfully.
```

Unchanged from prior fixes' dry-run output — this change touches no BPF
attachment code, so dry-run's only role here is confirming
`cmd/monitor/main.go` still compiles and runs correctly around the new
shutdown-reporting block. Raw:
[`dry-run-confirmation.txt`](evidence/dry-run-confirmation.txt).

A live reproduction of a real drop under an actual `npm install` (rather
than a synthetic fill loop) was not attempted: forcing genuine backpressure
against a 4096-entry channel needs either a slowed-down consumer or a burst
large enough to outrun it, neither of which the audit's own reproduction
steps or this project's existing test infrastructure provide a harness for.
Each test's fill-then-real-event pattern already exercises the exact
`select`/`default` code path production would hit, through the real
collector/BPF pipeline, which is what H2's and H4's equivalent tests also
settled for.
