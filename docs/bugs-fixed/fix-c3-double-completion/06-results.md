# 6. Results

## Goals vs. outcome

| # | Goal | Outcome |
|---|---|---|
| 1 | Exactly one completion per session | **met** — 8/300 duplicate deliveries → 0/300 |
| 2 | `TimedOut` set safely and correctly | **met** — unlocked write removed; loser cannot overwrite winner (pinned by slice 1) |
| 3 | Timer leak closed | **met** — `d.timers` never retains an entry for a timed-out session (teeth-checked) |
| 4 | Proven under real racing | **met** — 300-trial stress test at a 1µs timeout, repeatable |
| 5 | Nothing else changes | **met** — `-race` and root suites green, 9 packages |

## The measurement that matters

`TestDetectorNeverDeliversASessionMoreThanOnceWhenExitRacesTimeout`, 300
independent trials of exit racing a 1-microsecond session timeout:

**Before**

```
detector_test.go:613: session pid 20191 delivered on Completed() 2 times, want exactly 1
detector_test.go:613: session pid 20146 delivered on Completed() 2 times, want exactly 1
detector_test.go:613: session pid 20170 delivered on Completed() 2 times, want exactly 1
detector_test.go:613: session pid 20160 delivered on Completed() 2 times, want exactly 1
detector_test.go:613: session for pid 20120 delivered on Completed() 2 times, want exactly 1
detector_test.go:613: session pid 20213 delivered on Completed() 2 times, want exactly 1
detector_test.go:613: session pid 20192 delivered on Completed() 2 times, want exactly 1
detector_test.go:613: session pid 20116 delivered on Completed() 2 times, want exactly 1
detector_test.go:618: 8/300 sessions completed more than once
--- FAIL: TestDetectorNeverDeliversASessionMoreThanOnceWhenExitRacesTimeout (0.11s)
```

**After**

```
--- PASS: TestDetectorNeverDeliversASessionMoreThanOnceWhenExitRacesTimeout (0.11s)
PASS
```

8 duplicate `BuildRecord`/`Write` cycles per 300 installs, at this timeout
width, down to zero. Each duplicate previously meant one install's session
was written to disk twice under the same session-ID path
(`npm-<unix-second>`), the second write silently clobbering the first.

## Test results

| Package | Tests added | Result |
|---|---|---|
| `internal/session` (unit, `session_test.go`) | 3 functions | all pass |
| `internal/session` (detector, `detector_test.go`) | 3 functions | all pass |

Red → green: **2 genuine reds** (slice 1's build failure, slice 2's 8/300
duplicates), **1 guard confirmed to have teeth** (slice 3, leak reproduced on
revert), and **1 guard confirmed to have none for this bug** (slice 4,
documented and kept as an ordinary-case regression test instead).

## Whole-repository verification

```
$ go build ./...
BUILD OK

$ go test ./internal/session/... -v -count=1
--- PASS: TestDetector_NpmInstallLifecycle (0.10s)
--- PASS: TestDetector_ConcurrentSessionCwds (0.00s)
--- PASS: TestDetector_ContextCancellationClosesCompleted (0.00s)
--- PASS: TestDetector_SeedsTrackedRootPIDAndCompletesOnRootExit (0.00s)
--- PASS: TestDetector_ForkOnlyChildrenDoNotBlockCompletion (0.00s)
--- PASS: TestSessionTimeout (0.10s)
--- PASS: TestDetectorNeverDeliversASessionMoreThanOnceWhenExitRacesTimeout (0.11s)
--- PASS: TestSessionTimeoutClearsItsOwnTimerEntry (0.02s)
--- PASS: TestDetectorTimedOutStaysFalseWhenExitCompletesBeforeTheTimer (0.30s)
--- PASS: TestRouter_Multiplexing (0.00s)
--- PASS: TestRouter_ContextCancellation (0.00s)
--- PASS: TestRouter_UnknownPID (0.00s)
--- PASS: TestRouter_RaceConditions (0.00s)
--- PASS: TestConcurrency (0.00s)
--- PASS: TestSnapshotIsIndependentOfLaterMutation (0.00s)
--- PASS: TestSnapshotCopiesSessionIdentity (0.00s)
--- PASS: TestSnapshotIsRaceFreeUnderConcurrentWriters (0.02s)
--- PASS: TestMarkCompleteOnceHasExactlyOneWinner (0.00s)
--- PASS: TestMarkCompleteOnceSetsStateAtomicallyWithTimedOut (0.00s)
--- PASS: TestMarkCompleteOnceSecondCallDoesNotOverwriteTheFirstWinner (0.00s)
    (plus 17 unrelated pre-existing tests in the package — 36 total)
PASS
ok  github.com/aniruddha/npm-ebpf-monitor/internal/session  0.684s

$ go test -race ./... -count=1
ok  github.com/aniruddha/npm-ebpf-monitor/cmd/dataset/exporter   1.018s
ok  github.com/aniruddha/npm-ebpf-monitor/cmd/dataset/labeler    1.026s
ok  github.com/aniruddha/npm-ebpf-monitor/cmd/dataset/validator  1.010s
ok  github.com/aniruddha/npm-ebpf-monitor/cmd/monitor            1.015s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/collector     1.013s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/dataset       1.010s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/features      1.012s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/output        1.063s
ok  github.com/aniruddha/npm-ebpf-monitor/internal/session       1.801s

$ sudo -n /usr/bin/go test ./... -count=1
   (same 9 packages, all ok)
```

`go vet ./...` clean; `gofmt -l internal/session/` reports no new offenders
(`detector_test.go` was already unformatted before this work, per the C2
doc's note, and was not touched further by this change).

Raw: [`full-session-suite.txt`](evidence/full-session-suite.txt),
[`race-suite.txt`](evidence/race-suite.txt), [`root-suite.txt`](evidence/root-suite.txt).

## Diff size

| File | Change |
|---|---|
| `internal/session/session.go` | +`completeOnce sync.Once` field, +`State` on `Snapshot`, +`MarkCompleteOnce` method (~35 lines with comments) |
| `internal/session/detector.go` | `handleExit` and the timeout callback rewired onto `MarkCompleteOnce`; timer cleanup moved to run unconditionally |
| `internal/session/session_test.go` | +3 tests |
| `internal/session/detector_test.go` | +3 tests |

No BPF, no schema, no collector, no output-format changes.

## Status of the audit's Critical findings

| Finding | Status |
|---|---|
| C1 — `write_processes`/`read_processes` broken | fixed ([docs](../fix-c1-open-flags/)) |
| C2 — unlocked concurrent read in `BuildRecord` | fixed ([docs](../fix-c2-buildrecord-race/)) |
| C3 — session can be completed twice | **fixed** (this task) |
| C4 — malicious fixtures exported as benign | fixed ([docs](../fix-c4-ground-truth-labels/)) |

All four Critical findings from the original audit are now fixed. H1 (the
timer-leak half of C3) is closed as a side effect of this fix — see
[07-findings-not-fixed.md](07-findings-not-fixed.md) for the fresh re-check.

## What this unblocks

The other failure mode that would have bitten hardest during a long,
high-throughput corpus run: alongside C2's crash-on-concurrent-read, C3 meant
every session racing its own timeout could silently double-write its output
file and leak a `*time.Timer` for the life of the process. Both of the
concurrency-shaped Critical findings are now closed; what remains is the High/
Medium/Low items in [07-findings-not-fixed.md](07-findings-not-fixed.md),
none of which are Critical.
