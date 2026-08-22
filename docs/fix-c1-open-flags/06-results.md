# 6. Final results

## 6.1 Goals achieved

| Goal | Status | Proven by |
|------|--------|-----------|
| 1. Open flags survive kernel → userspace | **Achieved** | `TestFileCollectorReportsOpenFlagsFromRealOpenat` |
| 2. `O_RDWR` counts as both reader and writer | **Achieved** | `TestFiletopAggregatorCountsReadWriteOpensAsBoth` |
| 3. `write_processes > 0` for a real `npm install` | **Achieved** | `TestFiletopAggregatorCountsWritersDuringRealNpmInstall` |
| 4. Wire format cannot silently drift | **Achieved** | `TestFileEventLayoutMatchesBPFStruct` |

All four. Nothing was dropped or redefined mid-flight.

## 6.2 The headline measurement

Same test, same workload, same machine; only the BPF object differs.

| Metric | Before | After |
|--------|--------|-------|
| File events captured | 1,473 | 1,473 |
| Events carrying non-zero flags | **0** | **1,469** |
| `read_processes` | 1 | 1 |
| `write_processes` | **0** | **1** |
| `file_access_processes` | 1 | 1 |

The 4 events with zero flags after the fix are genuine `O_RDONLY` opens with no
additional flags — `O_RDONLY` *is* `0`. Before the fix, `0 of 1,473` is C1 stated as a
number: the field was not merely wrong, it was never populated at all.

## 6.3 Test suite status

```
$ go test -race ./... -count=1
ok  github.com/aniruddha/npm-ebpf-monitor/cmd/monitor          1.034s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/collector   1.030s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/features    1.034s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/output      1.030s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/session     1.270s

$ sudo -n /usr/bin/go test ./... -count=1
ok  github.com/aniruddha/npm-ebpf-monitor/cmd/monitor          0.009s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/collector   0.534s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/features    2.663s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/output      0.010s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/session     0.235s
```

Clean under the race detector, and clean as root where the three privileged tests
actually execute rather than skip. No pre-existing test was modified or deleted; the
four existing `filetop` tests still pass unchanged.

Full logs: [`evidence/race-suite.txt`](evidence/race-suite.txt),
[`evidence/root-suite.txt`](evidence/root-suite.txt),
[`evidence/c1-tests.txt`](evidence/c1-tests.txt).

## 6.4 What this does and does not fix

**Fixed.** `write_processes` and `read_processes` are now derived from real `openat`
flags. Two of the 36 QUT-DV25 features stop being a constant and a near-constant.

**Not fixed, and important:**

- **The existing `sessions/*.json` corpus is still wrong.** Every session captured
  before this change recorded `write_processes: 0` and an inflated `read_processes`.
  Those values are not recoverable by re-processing — the flags were never written to
  disk. **The corpus must be re-captured**, and any CSV or trained model derived from
  it is built on two bad columns.
- **The monitor binary does not currently run on this kernel** for an unrelated
  pre-existing reason — see
  [07-out-of-scope-blocker.md](07-out-of-scope-blocker.md). Re-capturing the corpus is
  blocked on that being fixed first.
- **Other audit findings are untouched.** C2 (unlocked `BuildRecord`), C3 (double
  session completion), C4 (fixture mislabelling) and the High findings all stand.
- **`read_data_transfer_kb` / `write_data_transfer_kb` remain approximations**, as the
  package documentation already states.

## 6.5 Recommended follow-ups, in order

1. **Fix the ProcessTracer load failure** — nothing else can be validated end-to-end
   until the binary starts. Root cause and a suggested fix are in
   [07-out-of-scope-blocker.md](07-out-of-scope-blocker.md).
2. **Re-capture the session corpus** and re-export the CSV. Discard or clearly quarantine
   the old one.
3. **Run the test suite as root in CI.** The three tests that actually exercise the
   kernel path skip silently when unprivileged, which means an unprivileged `go test
   ./...` reports all-green in exactly the situation this bug lived in.
4. **Install `llvm-strip`** and wire the `Makefile`'s pinned toolchain into the generate
   step, removing the `BPF2GO_STRIP` workaround.
5. **Apply the same layout-guard pattern** to `ProcessEvent`, `SyscallEvent` and
   `TcpEvent`. All three share the identical `binary.Read` fragility that let C1 hide.

## 6.6 Files changed

```
 bpf/file_monitor.bpf.c                        |  7 ++++--   (+6 −1)
 internal/collector/filemonitor_x86_bpfel.go   |  regenerated
 internal/collector/filemonitor_x86_bpfel.o    |  regenerated
 internal/features/filetop_aggregator.go       |  6 +++--   (+4 −2)
 internal/features/filetop_aggregator_test.go  |  +17       (new test)
 internal/collector/file_collector_test.go     |  new file  (2 tests)
 internal/features/filetop_npm_e2e_test.go     |  new file  (1 test)
 docs/fix-c1-open-flags/                       |  new       (this directory)
```

Total production-code change: **10 lines across 2 source files.** The remainder is the
compiled artifact, tests, and documentation.
