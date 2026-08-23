# 4. How it was done, step by step

## Step 1 — locate and understand the defect

Read `AUDIT.md`'s Medium finding, then read the fork handler in
`bpf/process_tracer.bpf.c` alongside the exec and exit handlers in the same
file. The exit handler's own comment ("tracked_pids stores tgids, not
individual thread ids") made the convention explicit; grepping `is_tracked(`
across `syscall_tracer.bpf.c`, `file_monitor.bpf.c`, `tcp_monitor.bpf.c`
confirmed every other reader of the map resolves `bpf_get_current_pid_tgid()>>32`
before looking anything up. The fork handler, using `ctx->parent_pid` directly,
was the one place not following that convention.

Confirmed from the kernel side too: `trace_sched_process_fork`'s format sets
`__entry->parent_pid = parent->pid`, and in `task_struct`, `pid` is the thread
id while `tgid` is the thread-group id every thread shares. For a
single-threaded process the two numbers are identical, which is why this had
never surfaced.

## Step 2 — decide the reproduction has to be deterministic

The obvious first idea — reuse the existing test's `exec.Command`-based fork
and just seed only the tgid — was tried mentally and rejected before writing
any code. `exec.Command`'s fork runs on whatever OS thread the Go runtime
happens to schedule it on; sometimes that would be the process's main thread
(bug invisible), sometimes not (bug visible). A test that passes or fails
depending on Go's scheduler is not a red you can trust, and a red you can't
trust is not a red at all.

This is why `internal/collector/testdata/fork_from_thread.c` exists: a pthread
that calls `fork()` is *guaranteed* not to be the process's thread-group
leader, by definition — the leader's tid always equals the process's own pid,
and a pthread's tid never does. Reproducing the bug this way turns "sometimes
flaky" into "every single time."

## Step 3 — write and smoke-test the C fixture, standalone, before touching Go

```
$ cc -Wall -Wextra -pthread -o /tmp/check testdata/fork_from_thread.c
$ /tmp/check
PARENT_PID=713257
CHILD_PID=713259
```

Two different numbers, confirming the fixture genuinely forks a new process
from a non-leader thread, independent of any BPF code. Compiling with `-Wall
-Wextra` and getting no warnings before wiring it into a test caught mistakes
early and cheaply.

## Step 4 — write the failing test

`TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess`, described
in [02-tests.md](02-tests.md). Seeds `tracked_pids` with only the parent's pid
— read directly off the fixture's own stdout, not assumed — specifically to
avoid quietly reproducing the workaround being replaced.

## Step 5 — run the existing test as a control, unmodified, before changing anything

```
$ sudo -n /usr/bin/go test ./internal/collector/ -run TestProcessCollectorReportsForkOfTrackedProcess -v
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.94s)
```

This was deliberate, not incidental: it confirms in the record that the
existing coverage passes *despite* the bug, which is the evidence for why a new
test was necessary rather than reusing the old one. Raw:
[`evidence/pre-fix-workaround-still-passes.txt`](evidence/pre-fix-workaround-still-passes.txt).

## Step 6 — run the new test red

```
$ sudo -n /usr/bin/go test ./internal/collector/ -run TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess -v -timeout 30s
process_collector_test.go:285: no FORK event for child pid 713570 within 5s
    (forked from a non-leader thread of tracked tgid 713568)
--- FAIL (5.84s)
```

Red for the predicted reason: the event genuinely never arrives, not a compile
error, not an assertion on the wrong field. Raw:
[`evidence/red-fork-lookup.txt`](evidence/red-fork-lookup.txt).

## Step 7 — implement

The diff in [03-what-was-done.md](03-what-was-done.md).

## Step 8 — regenerate, and account for every object bpf2go touches

```
$ BPF2GO_STRIP=/usr/bin/strip go generate ./internal/collector/...
```

This rebuilds all four BPF programs regardless of which `.bpf.c` changed — a
known gotcha, recorded in memory from the earlier fixes. Checked each of the
other three against what they were immediately before this regeneration:

- `filemonitor_x86_bpfel.o` came back byte-identical (same md5 as before the
  regen) — no action needed.
- `syscalltracer_x86_bpfel.{o,go}` and `tcpmonitor_x86_bpfel.{o,go}` came back
  with *different* bytes than immediately before the regen, despite their
  `.bpf.c` sources being untouched. Before assuming a blind `git checkout --`
  was safe (it is not, in general — the working tree here carries substantial
  uncommitted work from earlier tasks that a naive revert to `HEAD` would
  destroy), checked whether `HEAD`'s copy of each file matched what the file
  had been *immediately before this regeneration*:

  ```
  $ git show HEAD:internal/collector/syscalltracer_x86_bpfel.o | md5sum
  90a34777dcc0d27de0ecc0d569a4094f    # matches pre-regen exactly
  $ git show HEAD:internal/collector/tcpmonitor_x86_bpfel.o | md5sum
  e46012aa39434bb08a43e012e2324478    # matches pre-regen exactly
  ```

  Both matched, meaning the working tree held no uncommitted changes to these
  two files before this regeneration — so `git checkout --` on exactly these
  four paths was verified-safe, not assumed-safe, and restored them to the
  precise pre-regen bytes.
- `processtracer_x86_bpfel.o` differs, as intended — this is the fix.
  `processtracer_x86_bpfel.go` came back byte-identical to `HEAD`, since this
  change alters control flow, not any struct layout bpf2go generates Go bindings
  for.

Raw: [`evidence/checksums.txt`](evidence/checksums.txt).

## Step 9 — run it green

```
$ sudo -n /usr/bin/go test ./internal/collector/ -run \
    'TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess|TestProcessCollectorReportsForkOfTrackedProcess|TestNewProcessCollectorLoadsAndAttaches' -v
--- PASS: TestNewProcessCollectorLoadsAndAttaches (0.40s)
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.75s)
--- PASS: TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess (0.64s)
```

`TestNewProcessCollectorLoadsAndAttaches` passing here is not incidental
either: `bpf_get_current_pid_tgid()` is a long-stable helper already used
throughout this codebase, but the project has been burned before by an
assumption that a change "obviously" wouldn't affect verifier acceptance (the
[ProcessTracer load-failure fix](../fix-processtracer-fork-load/)), so this was
checked explicitly rather than inferred from the fork test alone passing. Raw:
[`evidence/green-fork-tests.txt`](evidence/green-fork-tests.txt).

## Step 10 — tighten the existing test, now that its workaround is unnecessary

Removed the every-tid seeding and the now-dead `selfTaskIDs` helper, replaced
with seeding `os.Getpid()` alone, and ran it three times in a row rather than
once — this test's only value now is proving the fix generalises beyond the
synthetic fixture to the way Go's own runtime forks, and a single pass would
not have ruled out the scheduling luck this whole task exists to eliminate as a
testing strategy.

```
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.93s)
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.94s)
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.89s)
```

## Step 11 — verify the whole repository

```
$ go build ./...                             BUILD OK
$ go test -race ./... -count=1               all ok
$ sudo -n /usr/bin/go test ./... -count=1    all ok
```

Raw: [`evidence/race-suite.txt`](evidence/race-suite.txt),
[`evidence/root-suite.txt`](evidence/root-suite.txt).

## Step 12 — regression-check the ordinary case against the real binary

```
$ sudo -n /usr/bin/go run ./cmd/monitor -output-dir <out> -verbose -session-timeout 60s &
$ cd <proj> && npm install lodash --no-audit --no-fund
added 1 package in 914ms
```

```json
"process_tree": "npm(716941)",
"write_processes": 1,
```

A normal install never forks from a non-leader thread, so this exercises goal
3 (no regression) rather than goal 1 (the fix itself) — recorded honestly as
such in [02-tests.md](02-tests.md) rather than presented as proof of the fix.

Raw: [`evidence/e2e-regression-session-lodash.json`](evidence/e2e-regression-session-lodash.json).
