# 2. Tests

Three tests are relevant to this fix: one new, and two pre-existing tests that
were run as controls — one of which was then tightened.

All three use `go test` against the real kernel this machine is running,
consistent with the [C1](../fix-c1-open-flags/) and
[ProcessTracer](../fix-processtracer-fork-load/) fixes: the defect lives in
kernel-facing BPF code, so the seam that tells the truth is the real kernel,
not a hand-built struct.

---

## Test 1 (new, the TDD slice) — `TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess`

Reproduces the audited scenario directly and deterministically, using a small
C fixture rather than relying on Go runtime scheduling. See
[03-what-was-done.md](03-what-was-done.md) for why a fixture was necessary.

`internal/collector/testdata/fork_from_thread.c`: a process that creates one
pthread, calls `fork()` from inside it, and prints `PARENT_PID=<pid>` before the
fork and `CHILD_PID=<pid>` after, flushing each immediately.

The test:

1. Compiles the fixture (skips if no C compiler is available).
2. Loads the real ProcessTracer BPF programs.
3. Runs the fixture, reads `PARENT_PID` off its stdout.
4. Seeds `tracked_pids` with **only** that one pid — deliberately not every
   thread id, because the whole point is to test the lookup a correct,
   TGID-only population would exercise.
5. Reads `CHILD_PID` off stdout — by this point `fork()` inside the pthread has
   already returned in the fixture.
6. Waits up to 5s for a `FORK` event (`EventType == 1`) whose `Pid` matches
   `CHILD_PID`, and asserts its `Ppid` equals the seeded parent pid.

**Result: achieved.**

Before the fix: timed out.

```
process_collector_test.go:285: no FORK event for child pid 713570 within 5s
    (forked from a non-leader thread of tracked tgid 713568)
```

After the fix: passes.

```
--- PASS: TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess (0.64s)
```

Raw: [`evidence/red-fork-lookup.txt`](evidence/red-fork-lookup.txt),
[`evidence/green-fork-tests.txt`](evidence/green-fork-tests.txt).

---

## Test 2 (control, run before the fix) — the pre-existing test, unmodified

Before touching any source, `TestProcessCollectorReportsForkOfTrackedProcess`
was run as-is against the unfixed BPF program, to check what the existing
coverage actually proved.

**Result: it passed.** Which is the point being made, not a surprise: its
comment already said why —

> The sched_process_fork tracepoint reports parent_pid as the forking task's
> *thread* id, not its thread-group id, and Go may run the fork from any
> runtime thread. Seeding every tid makes the test independent of which thread
> the runtime happens to pick.

That test seeded **every** tid under `/proc/self/task`, so whichever thread the
Go runtime happened to fork `exec.Command`'s child from, the lookup would find
a match regardless of the bug. It is a real test of "forking produces the
right event data" — genuinely useful, and left as-is — but it could not have
caught this specific defect, because it was unknowingly built to route around
it.

Raw: [`evidence/pre-fix-workaround-still-passes.txt`](evidence/pre-fix-workaround-still-passes.txt).

This is the same shape of finding as the C1 fix's central insight — a green
test that looks like coverage of the thing that is actually broken — except
here the workaround was written *knowingly* (the comment says so), as the only
way available at the time to get a passing fork test at all. It just happened
to also hide the very bug it was working around.

---

## Test 3 (tightened after the fix) — the same pre-existing test, minus the workaround

Once the fix was green, the workaround was removed: the test now seeds only
`os.Getpid()` — the process's own tgid — exactly as a correct caller would.

```go
tracked := pc.TrackedPidsMap()
one := uint32(1)
selfPID := uint32(os.Getpid())
if err := tracked.Update(&selfPID, &one, ebpf.UpdateAny); err != nil {
    t.Fatalf("seed tgid %d: %v", selfPID, err)
}
```

This exercises a second, independent path through the same fix:
`exec.Command`'s fork runs on whichever OS thread the Go runtime schedules it
on, which is not guaranteed to be the process's main thread. Passing here shows
the fix holds for that case too, not just for the deterministic C fixture.

**Result: achieved**, and checked for flakiness by running it three times in a
row rather than once:

```
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.93s)
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.94s)
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.89s)
```

The now-unused `selfTaskIDs` helper was deleted along with the workaround.

---

## Regression check — a real `npm install` through the real monitor binary

Not a Go test. Started the actual `cmd/monitor` binary as root, ran
`npm install lodash --no-audit --no-fund` against it, and read the resulting
session file.

```json
"process_tree": "npm(716941)",
"write_processes": 1,
```

An ordinary install is single-threaded at every fork, so `ctx->parent_pid`
happened to equal the tgid even before the fix — this exercises goal 3, not
goal 1, and it confirms the fix changes nothing about the common path.

Raw: [`evidence/e2e-regression-session-lodash.json`](evidence/e2e-regression-session-lodash.json),
[`evidence/e2e-monitor-session-line.txt`](evidence/e2e-monitor-session-line.txt).

---

## Goal coverage

| Goal | Covered by | Achieved |
|---|---|---|
| 1 — resolve tgid regardless of forking thread | Test 1 | yes |
| 2 — deterministic, non-leader-thread reproduction | Test 1 (C fixture, not runtime luck) | yes |
| 3 — no regression to the ordinary case | Test 3 (3× stable), real `npm install` | yes |
| 4 — loads cleanly | `TestNewProcessCollectorLoadsAndAttaches`, full root suite | yes |
