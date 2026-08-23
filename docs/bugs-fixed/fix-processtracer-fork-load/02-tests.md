# 2. The tests, and whether the goals were achieved

Two tests were written, both TDD slices — written failing, then made to pass. A third
relevant test (`TestProcessEventLayoutMatchesBPFStruct`) already existed and was left
alone.

All tests use the standard `testing` package: `t.Helper()` on the fixtures, `t.Cleanup`
for teardown so resources are released even on `t.Fatal`, `t.Skip` for the privilege
and dependency gates, and `t.Errorf` where a test should report every violated
expectation rather than stopping at the first.

## Summary

| # | Test | Goal | Went red first? | Achieved? |
|---|------|------|-----------------|-----------|
| 1 | `TestNewProcessCollectorLoadsAndAttaches` | Goal 1 | Yes | **Yes** |
| 2 | `TestProcessCollectorReportsForkOfTrackedProcess` | Goal 2 | Yes | **Yes** |
| 3 | Manual end-to-end run of the `monitor` binary | Goal 3 | Yes (binary exited 1) | **Yes** |

All three goals achieved.

Both tests live in `internal/collector/process_collector_test.go`, alongside the
pre-existing layout guard.

---

## Test 1 — the collector loads and attaches

**Goal 1.** The narrowest possible statement of "the monitor can start".

```go
func TestNewProcessCollectorLoadsAndAttaches(t *testing.T) {
	requireRoot(t)

	pc, err := NewProcessCollector()
	if err != nil {
		t.Fatalf("NewProcessCollector() = %v, want nil", err)
	}
	t.Cleanup(func() { pc.Close() })
}
```

**Seam choice.** The test drives `NewProcessCollector()`, not the generated
`LoadProcessTracer()`. That constructor is the public boundary `main.go` actually calls,
and it does the three things that must all succeed: verify and load the programs, attach
all three tracepoints, and open the ring buffer. Testing the generated loader directly
would assert against bpf2go's output — implementation detail — and would not have caught
an attach failure.

**Red** — [`evidence/red-load-failure.txt`](evidence/red-load-failure.txt):

```
process_collector_test.go:105: NewProcessCollector() = load ProcessTracer objects:
  field TracepointSchedSchedProcessFork: program tracepoint__sched__sched_process_fork:
  load program: invalid argument: invalid func unknown#195896080 (77 line(s) omitted),
  want nil
--- FAIL: TestNewProcessCollectorLoadsAndAttaches (0.10s)
```

**Green:** `--- PASS ... (0.21s)`.

---

## Test 2 — fork events still carry their data

**Goal 2.** This is the test that constrains *how* Goal 1 may be met.

It seeds `tracked_pids`, forks a real child via `exec.Command("/bin/sleep", "0.2")`,
then drains `pc.Events` looking for a FORK event (`EventType == 1`) matching the child's
pid, and asserts on `Ppid` and `Comm`.

```go
if evt.Ppid == 0 {
	t.Errorf("FORK event Ppid = 0, want the forking task's pid")
}
if got := decodeComm(evt.Comm); got != wantComm {
	t.Errorf("FORK event Comm = %q, want %q", got, wantComm)
}
```

`wantComm` is read from `/proc/self/comm` — an independent source of truth, not a value
recomputed the way the implementation computes it.

**Two details the test had to get right, both discovered by reading the kernel's
tracepoint definition rather than by guessing:**

1. **`parent_pid` is a thread id, not a thread-group id.** The tracepoint records
   `parent->pid`, and Go may run the fork from any runtime thread, while `tracked_pids`
   is keyed by tgid. The test therefore seeds *every* tid in `/proc/self/task`, making
   it independent of which thread the runtime picks. (This mismatch is itself a latent
   defect — see [07-findings-not-fixed.md](07-findings-not-fixed.md).)

2. **The assertion on `Comm` is what makes "just delete the line" fail.** A child
   inherits its parent's comm and keeps it until it execs, so the expected value is the
   *test binary's* comm, captured before the fork.

**Red** — [`evidence/red-load-failure.txt`](evidence/red-load-failure.txt): fails at
the constructor, same poison error.

**Green:** `--- PASS ... (0.63s)`, with `Comm` matching `/proc/self/comm` exactly. That
pass is also the empirical confirmation of the claim the fix rests on — that
`bpf_get_current_comm()` reports the same string `ctx->child_comm` would. The claim was
derived from the kernel source; the test is what makes it a verified fact rather than
an argument.

---

## Test 3 — the end-to-end run (manual)

**Goal 3.** Not automated. The monitor is a long-running privileged daemon that
attaches system-wide tracepoints and writes session files on a timeout; wrapping that
in `go test` would have produced a slow, flaky test that asserts very little per second
of runtime.

Performed instead as a recorded manual procedure — full transcript in
[06-results.md](06-results.md), artefacts in
[`evidence/monitor-startup.txt`](evidence/monitor-startup.txt) and
[`evidence/post-fix-session.json`](evidence/post-fix-session.json).

**Before:** binary exits 1 on startup, no session ever written.
**After:** binary reaches `npm-ebpf-monitor active. Watching npm install...`, detects the
install, and writes a session reporting `"write_processes": 1`.

---

## What was deliberately *not* tested

- **That `bpf_get_current_comm()` equals `ctx->child_comm` on an *old* kernel.** Not
  reachable from here — the old layout is exactly what this machine's kernel no longer
  has. The equivalence argument rests on the kernel source (the tracepoint fires in
  `copy_process()` with `current` == the forking task, and the child's comm is a copy of
  the parent's until exec) and is confirmed on this kernel by Test 2.
- **The `__data_loc` decoding path.** It was considered and rejected as the fix, so
  there is nothing to test. See
  [05-why-this-approach.md](05-why-this-approach.md#why-not-decode-__data_loc).
- **The two newly found defects** in
  [07-findings-not-fixed.md](07-findings-not-fixed.md). Testing them would have meant
  fixing them, which would have widened this change.
