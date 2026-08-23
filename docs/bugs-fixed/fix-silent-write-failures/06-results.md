# 6. Results

## Goals vs. outcome

| # | Goal | Outcome |
|---|---|---|
| 1 | Count what was persisted and what was lost | **met** — `outputStats{written, failed}`, asserted over 3 subtests |
| 2 | Say so at shutdown | **wired** — counts printed on both paths; not exercised end to end (see below) |
| 3 | Exit non-zero when a session was lost | **met** for the decision (4 subtests); the `os.Exit` call itself verified by inspection |
| 4 | Do not abort the run on a single failure | **met** — `failed == 3` from a 3-session batch proves every session was attempted |
| 5 | Change nothing else | **met** — full suite green under `-race` and under root |

## Behaviour, before and after

The worker log lines below are captured verbatim from the `all writes fail`
subtest ([`evidence/worker-failure-logs.txt`](evidence/worker-failure-logs.txt)).
The shutdown lines come from `main`, which cannot be unit-tested — they are
quoted from the source, not from a run; see
[07-findings-not-fixed.md](07-findings-not-fixed.md).

**Before** — three sessions collected, all three unwritable:

```
2026/08/22 21:09:09 write session npm-1787400000: mkdir <tmp>/blocker: not a directory
2026/08/22 21:09:09 write session npm-1787400001: mkdir <tmp>/blocker: not a directory
2026/08/22 21:09:09 write session npm-1787400002: mkdir <tmp>/blocker: not a directory
```

Three lines among the monitor's ordinary chatter. Nothing at shutdown. Exit
status `0`. Output directory: empty. `stats` did not exist — the worker returned
nothing at all.

**After** — the same three sessions produce the same three lines, plus, at
shutdown:

```
LOST 3 of 3 session(s): they were collected but could not be written
```

and exit status `1`, from `os.Exit(exitCodeForOutput(outStats))`.

The clean-run half is the part that makes the count usable day to day:

```
Wrote 12 session record(s).
```

## Test results

```
=== RUN   TestLoadInstallFeaturesUsesSessionCwd
--- PASS: TestLoadInstallFeaturesUsesSessionCwd (0.00s)
=== RUN   TestLoadInstallFeaturesMissingCwd
--- PASS: TestLoadInstallFeaturesMissingCwd (0.00s)
--- PASS: TestRunOutputWorkerReportsWriteOutcomes (0.00s)
    --- PASS: .../all_writes_succeed (0.00s)
    --- PASS: .../all_writes_fail (0.00s)
    --- PASS: .../no_sessions_at_all (0.00s)
--- PASS: TestExitCodeForOutputFailsWhenSessionsWereLost (0.00s)
    --- PASS: .../nothing_written,_nothing_failed (0.00s)
    --- PASS: .../everything_written (0.00s)
    --- PASS: .../one_session_lost (0.00s)
    --- PASS: .../everything_lost (0.00s)
PASS
ok  	github.com/aniruddha/npm-ebpf-monitor/cmd/monitor	0.006s
```

Red → green: **build failure (8 compiler errors) → 7 subtests passing**, with
the two pre-existing tests unaffected.

## Whole-repository verification

```
$ go build ./...
BUILD OK

$ go test -race ./... -count=1
ok  	.../cmd/monitor          1.038s
ok  	.../internal/collector   1.020s
ok  	.../internal/features    1.031s
ok  	.../internal/output      1.072s
ok  	.../internal/session     1.252s

$ sudo -n /usr/bin/go test ./... -count=1
ok  	.../cmd/monitor          0.010s
ok  	.../internal/collector   1.460s
ok  	.../internal/features    2.712s
ok  	.../internal/output      0.017s
ok  	.../internal/session     0.225s
```

`-race` is the load-bearing one for this change, since `outStats` is written on
the output-worker goroutine and read on the main goroutine after `wg.Wait()`.
Clean.

`gofmt` clean on both changed files; `go vet ./cmd/monitor/` clean.

## Diff size

| File | Change |
|---|---|
| `cmd/monitor/main.go` | +`outputStats`, +`exitCodeForOutput`, worker signature and return, 2 counters, call site, 8-line shutdown block |
| `cmd/monitor/main_test.go` | +2 imports, +2 helpers, +2 tests |

No BPF source, no regenerated object, no output-format change, no other package
touched.

## Status of the audit's silent-loss problem

The failure mode described in `AUDIT.md` had two halves:

| Half | Fixed by | Status |
|---|---|---|
| Package specs with `/` made every such write fail | [previous task](../fix-output-filename-sanitization/) | fixed |
| Any write failure was invisible and exit-zero | this task | fixed |

## What this unblocks

Re-capturing the session corpus, which was the reason for doing this first. That
run can now be scripted against the monitor's exit status, and an incomplete
corpus stops the pipeline instead of quietly becoming training data.
