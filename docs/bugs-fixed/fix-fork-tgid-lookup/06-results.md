# 6. Results

## Goals vs. outcome

| # | Goal | Outcome |
|---|---|---|
| 1 | Resolve tgid regardless of which thread forked | **met** — deterministic non-leader-thread fork now produces the FORK event |
| 2 | Prove it without relying on scheduling luck | **met** — C fixture guarantees the forking thread is never the leader |
| 3 | No regression to the ordinary case | **met** — 3× stable existing-test run; real `npm install` session unchanged in shape |
| 4 | Loads cleanly | **met** — `TestNewProcessCollectorLoadsAndAttaches` passes; full root suite green |

## The measurement that matters

Same scenario, same test, before and after the one-line lookup fix (the
seven-line comment explaining it aside):

**Before:**

```
process_collector_test.go:285: no FORK event for child pid 713570 within 5s
    (forked from a non-leader thread of tracked tgid 713568)
--- FAIL: TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess (5.84s)
```

**After:**

```
--- PASS: TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess (0.64s)
```

And the pre-existing test's workaround, which had silently been carrying the
bug's absence of coverage for as long as it existed, removed and re-verified
stable:

```
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.93s)
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.94s)
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.89s)
```

## Test results

```
$ sudo -n /usr/bin/go test ./internal/collector/ -run \
    'TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess|TestProcessCollectorReportsForkOfTrackedProcess|TestNewProcessCollectorLoadsAndAttaches' -v
--- PASS: TestNewProcessCollectorLoadsAndAttaches (0.40s)
--- PASS: TestProcessCollectorReportsForkOfTrackedProcess (0.75s)
--- PASS: TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess (0.64s)
PASS
ok  	github.com/aniruddha/npm-ebpf-monitor/internal/collector	1.793s
```

## Whole-repository verification

```
$ go build ./...
BUILD OK

$ go test -race ./... -count=1
ok  	.../cmd/monitor          1.022s
ok  	.../internal/collector   1.021s
ok  	.../internal/features    1.028s
ok  	.../internal/output      1.053s
ok  	.../internal/session     1.257s

$ sudo -n /usr/bin/go test ./... -count=1
ok  	.../cmd/monitor          0.008s
ok  	.../internal/collector   2.044s
ok  	.../internal/features    2.673s
ok  	.../internal/output      0.019s
ok  	.../internal/session     0.231s
```

`gofmt` clean on both changed Go files; `go vet ./internal/collector/` clean.

## BPF object checksums

| Object | Before this task | After this task |
|---|---|---|
| `filemonitor_x86_bpfel.o` | `8f46c915…` | `8f46c915…` (unchanged) |
| `processtracer_x86_bpfel.o` | `5454e806…` | `a23faa25…` (this fix) |
| `syscalltracer_x86_bpfel.o` | `90a34777…` | `90a34777…` (unchanged) |
| `tcpmonitor_x86_bpfel.o` | `e46012aa…` | `e46012aa…` (unchanged) |

Full table: [`evidence/checksums.txt`](evidence/checksums.txt).

## Real-binary regression check

```json
"process_tree": "npm(716941)",
"write_processes": 1,
```

Structurally identical in shape to sessions captured before this fix — the
ordinary single-thread-forks-from-its-own-thread path is untouched.

## Diff size

| File | Change |
|---|---|
| `bpf/process_tracer.bpf.c` | 1 field read → 1 helper call, +19-line explanatory comment |
| `internal/collector/testdata/fork_from_thread.c` | new, ~60 lines |
| `internal/collector/process_collector_test.go` | +1 test, +2 helpers, -1 helper (`selfTaskIDs`), 1 existing test tightened |
| `internal/collector/processtracer_x86_bpfel.o` | regenerated |

No other BPF program, no output format, no collector API changed.

## Status of the audit finding

| Finding | Status |
|---|---|
| Medium — fork handler filters a tid against a tgid-keyed map | **fixed**, demonstrated deterministically (previously "not demonstrated in production") |

`AUDIT.md`'s addendum has been updated to mark this fixed; see the diff
described in this task's closing steps.
