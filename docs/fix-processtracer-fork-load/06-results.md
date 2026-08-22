# 6. Final results

## 6.1 Goals achieved

| Goal | Status | Proven by |
|------|--------|-----------|
| 1. Monitor starts on the running kernel | **Achieved** | `TestNewProcessCollectorLoadsAndAttaches` |
| 2. Fork events keep pid, ppid and comm | **Achieved** | `TestProcessCollectorReportsForkOfTrackedProcess` |
| 3. End-to-end validation finally runs | **Achieved** | Session JSON with `write_processes: 1` |

All three. Nothing dropped or redefined mid-flight.

## 6.2 The monitor starts

Before — the binary exits during startup, having captured nothing:

```
load ProcessTracer: load ProcessTracer objects: field TracepointSchedSchedProcessFork:
  program tracepoint__sched__sched_process_fork:
  load program: invalid argument: invalid func unknown#195896080
exit status 1
```

After — [`evidence/monitor-startup.txt`](evidence/monitor-startup.txt):

```
loaded process, syscall, file, and TCP collectors
npm-ebpf-monitor active. Watching npm install...
```

## 6.3 The end-to-end validation that was blocked

Procedure (reproducible):

```bash
sudo -n /usr/bin/go run ./cmd/monitor -output-dir <out> -session-timeout 20s -verbose &
cd <proj> && npm install lodash --no-audit --no-fund
# wait out the session timeout
```

The monitor detected the install, tracked it, and wrote
[`evidence/post-fix-session.json`](evidence/post-fix-session.json):

```json
"filetop": {
  "read_processes": 1,
  "write_processes": 1,
  "read_data_transfer_kb": 315,
  "write_data_transfer_kb": 2,
  "file_access_processes": 1
}
```

Against the four `lodash` sessions committed in `sessions/`, all captured before the C1
fix:

| Session | `read_processes` | `write_processes` |
|---------|------------------|-------------------|
| `npm-1773841683_lodash.json` | 1 | **0** |
| `npm-1774070156_lodash.json` | 1 | **0** |
| `npm-1774426161_lodash.json` | 1 | **0** |
| `npm-1774427962_lodash.json` | 1 | **0** |
| **new, post-fix** | 1 | **1** |

This is what the C1 work could not previously demonstrate. C1 was proven at the
collector and aggregator level; this is the first time it has been shown in a session
file written by the real binary during a real install. **Both fixes are now confirmed
end-to-end.**

`process_tree` reads `npm(684465)` with no children — unchanged from the pre-fix
sessions, and correct here: `lodash` has no install scripts, so npm spawns no
subprocesses. This is not a regression.

## 6.4 Test suite status

```
$ sudo -n /usr/bin/go test ./... -count=1
ok  github.com/aniruddha/npm-ebpf-monitor/cmd/monitor          0.004s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/collector   1.153s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/features    2.269s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/output      0.004s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/session     0.220s

$ go test -race ./... -count=1
ok  github.com/aniruddha/npm-ebpf-monitor/cmd/monitor          1.013s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/collector   1.014s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/features    1.015s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/output      1.018s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/session     1.248s
```

Clean as root, where the privileged tests execute rather than skip, and clean under the
race detector. No pre-existing test modified or deleted.

Logs: [`evidence/root-suite.txt`](evidence/root-suite.txt),
[`evidence/race-suite.txt`](evidence/race-suite.txt),
[`evidence/green-load-and-fork.txt`](evidence/green-load-and-fork.txt).

## 6.5 What this does and does not fix

**Fixed.** The monitor loads, attaches and runs on current kernels. Fork events carry
pid, ppid and comm. The C1 fix is confirmed end-to-end.

**Not fixed:**

- **`bpf/vmlinux.h` is still stale.** This program no longer depends on the part that
  diverged, but the header is unchanged and the same failure will recur for any future
  access to a field whose kind has changed. Signature to look for: `0xBAD2310`
  (`195896080`).
- **Two newly found defects**, recorded but not fixed —
  [07-findings-not-fixed.md](07-findings-not-fixed.md).
- **The historical `sessions/*.json` corpus is still wrong.** Every pre-fix session
  records `write_processes: 0`. Not recoverable by re-processing; must be re-captured.
  That is now *possible* — it was not before this fix.
- **Other audit findings stand.** C2 (unlocked `BuildRecord`), C3 (double session
  completion), C4 (fixture mislabelling) and the High findings are untouched.

## 6.6 Recommended follow-ups, in order

1. **Re-capture the session corpus** and re-export the CSV. This is now unblocked and is
   the highest-value next step — every downstream artifact depends on it. Note finding 1
   in [07-findings-not-fixed.md](07-findings-not-fixed.md) first: it will silently drop
   sessions for path-like package specs.
2. **Sanitise the output filename** (finding 1). A one-line fix that prevents silent
   data loss during that re-capture.
3. **Resolve the tid/tgid mismatch** (finding 2), which may be suppressing child-process
   tracking for multithreaded installs.
4. **Run the suite as root in CI.** Three tests here and three in the C1 work skip
   silently when unprivileged; an unprivileged `go test ./...` reported all-green
   throughout the entire period the monitor could not start at all.
5. **Regenerate `vmlinux.h`** and re-verify all four programs, closing the root cause.
6. **Install `llvm-strip`** and drop the `BPF2GO_STRIP` override.

## 6.7 Files changed

```
 bpf/process_tracer.bpf.c                      |  14 ++++++++--   (+13 −1, 12 of them comment)
 internal/collector/processtracer_x86_bpfel.o  |  regenerated
 internal/collector/process_collector_test.go  |  +140           (2 tests, 3 helpers)
 docs/fix-processtracer-fork-load/             |  new            (this directory)
```

Production-code change: **one statement.** The rest is the recompiled artifact, tests,
and documentation.
