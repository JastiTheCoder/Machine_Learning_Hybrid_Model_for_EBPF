# 2. The tests, and whether the goals were achieved

Four tests were written. Three are TDD slices (written failing, then made to pass);
one is a regression guard that passed on first run and is honestly labelled as such
rather than being counted as a slice.

## Summary

| # | Test | File | Goal | Went red first? | Achieved? |
|---|------|------|------|-----------------|-----------|
| 1 | `TestFiletopAggregatorCountsReadWriteOpensAsBoth` | `internal/features/filetop_aggregator_test.go` | Goal 2 | Yes | **Yes** |
| 2 | `TestFileEventLayoutMatchesBPFStruct` | `internal/collector/file_collector_test.go` | Goal 4 | No — guard, see below | **Yes** |
| 3 | `TestFileCollectorReportsOpenFlagsFromRealOpenat` | `internal/collector/file_collector_test.go` | Goal 1 | Yes | **Yes** |
| 4 | `TestFiletopAggregatorCountsWritersDuringRealNpmInstall` | `internal/features/filetop_npm_e2e_test.go` | Goal 3 | Yes | **Yes** |

All four goals were achieved. No goal was dropped, narrowed, or restated after the
fact.

---

## Test 1 — `O_RDWR` counts as both reader and writer

**Goal 2.** Pure unit test at the `FiletopAggregator` public API.

```go
agg := NewFiletopAggregator()
agg.Add(collector.FileEvent{Pid: 400, Flags: uint32(syscall.O_RDWR)})

got := agg.Snapshot()
// want ReadProcesses == 1 and WriteProcesses == 1
```

**Red:** reproduced by reverting the fix — see
[`evidence/red-slice1.txt`](evidence/red-slice1.txt):

```
filetop_aggregator_test.go:103: O_RDWR open: ReadProcesses = 0, want 1
--- FAIL: TestFiletopAggregatorCountsReadWriteOpensAsBoth (0.00s)
```

**Green:** passes. The expected values are independent literals (`1` and `1`), not a
recomputation of what the code does, so the test is not tautological.

---

## Test 2 — the Go/C wire format agrees

**Goal 4.** Asserts `unsafe.Sizeof(FileEvent{}) == 280` and pins every field offset:
`Pid=0`, `Filename=4`, `DirCategory=260`, `OpenSuccess=261`, `Pad=262`, `Flags=264`,
`TimestampNs=272`.

**This test passed the first time it was run, and is not counted as a TDD slice.**
It is a regression guard. It is included because it documents the contract that
`binary.Read` silently depends on: if someone adds a field to the C `struct file_event`
without updating the Go one, every subsequent field decodes as garbage and no existing
test would notice.

Writing it also produced the single most useful finding of the investigation: the
layout was **already correct**. `struct file_event` had always reserved a `__u32 flags`
at offset 264 and the Go side had always read it. The wire format was never the
problem — only the producer was. That ruled out an entire class of candidate fixes
before any code was written.

---

## Test 3 — real `openat()` flags reach userspace

**Goal 1.** This is the test that actually catches C1, and the only pure-Go test that
*can*. It skips unless running as root, because it loads a real BPF program.

What it does:

1. Removes the memlock rlimit and creates a `tracked_pids` hash map matching the BPF
   program's expectations.
2. Constructs a real `FileCollector` against that map and runs it.
3. Seeds its own PID into `tracked_pids` so the kernel-side filter lets its opens
   through.
4. Calls `syscall.Open(path, O_WRONLY|O_CREAT, 0o644)` — a genuine syscall, not a
   fabricated struct.
5. Drains `collector.Events` for up to 5s, asserting some event satisfies
   `evt.Flags&O_ACCMODE == O_WRONLY && evt.Flags&O_CREAT != 0`.

**Red:** reproduced by checking the pre-fix BPF object back out of git — see
[`evidence/red-slice3.txt`](evidence/red-slice3.txt):

```
file_collector_test.go:118: no O_WRONLY|O_CREAT file event observed for this
    process within 5s; open flags are not reaching userspace
--- FAIL: TestFileCollectorReportsOpenFlagsFromRealOpenat (5.55s)
```

**Green:** `--- PASS ... (0.52s)`.

---

## Test 4 — a real `npm install` reports writers

**Goal 3.** End-to-end, root-only, skipped if `npm` is absent. Builds a throwaway npm
project in `t.TempDir()` whose only dependency is a local directory, so it needs no
network.

It aggregates the real event stream **twice**:

- `fixed` — the events exactly as the kernel now delivers them.
- `preFix` — the same events with `Flags` forced to `0`, reproducing precisely what the
  kernel used to send.

The `preFix` copy is a built-in control. Asserting `preFix.WriteProcesses == 0` and
`fixed.WriteProcesses > 0` in the same run pins the difference on the flags themselves,
rather than on npm happening to behave differently between two runs.

Because ProcessTracer's fork propagation is broken on this kernel
([07-out-of-scope-blocker.md](07-out-of-scope-blocker.md)), the test seeds
`tracked_pids` itself by walking `/proc` for descendants of the npm process every 20ms.

**Red:** run against the pre-fix BPF object — see
[`evidence/red-e2e.txt`](evidence/red-e2e.txt):

```
file events captured: 1473 (with non-zero flags: 0)
PRE-FIX  (flags always 0): read_processes=1 write_processes=0 file_access_processes=1
POST-FIX (real flags):     read_processes=1 write_processes=0 file_access_processes=1
post-fix WriteProcesses = 0; npm install writes files, so must be > 0
--- FAIL
```

Note `with non-zero flags: 0` — 1,473 events captured, not one carrying a flag. That
is C1 stated as a measurement.

**Green:** see [`evidence/c1-tests.txt`](evidence/c1-tests.txt):

```
file events captured: 1473 (with non-zero flags: 1469)
PRE-FIX  (flags always 0): read_processes=1 write_processes=0 file_access_processes=1
POST-FIX (real flags):     read_processes=1 write_processes=1 file_access_processes=1
--- PASS: TestFiletopAggregatorCountsWritersDuringRealNpmInstall (2.68s)
```

The 4 remaining zero-flag events are `openat` calls that genuinely used `O_RDONLY`
with no additional flags, which is `0`.

---

## What was deliberately *not* tested

- **The `read_processes` inflation itself.** It is arithmetically implied by Goal 1 —
  once flags are real, the `O_RDONLY` branch stops matching every event. Adding a
  test that asserts "`read_processes` is now smaller" would depend on a specific
  workload's read/write mix and would be fragile without adding information.
- **The `pending_opens` leak** (audit finding H1). Real, but a different finding;
  testing it here would have widened the scope of this change.
