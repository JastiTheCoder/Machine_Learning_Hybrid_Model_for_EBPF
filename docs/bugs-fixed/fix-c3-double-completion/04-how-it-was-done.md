# 4. How it was done — four slices

## Step 0 — verify the audit's claims rather than trust them

Read `handleExit`, the `time.AfterFunc` callback inside `startSessionTimer`,
and `HandleProcess`'s locking around both. Confirmed directly:

- Both completion paths take only the *read* side of `completedMu`
  (`RLock`), which is why `RWMutex` provides no mutual exclusion between
  them — any number of readers can hold it simultaneously, which is the
  entire audit claim in one sentence.
- `s.TimedOut = true` in the timeout callback is a bare, unlocked field write
  — a second, independent bug from the double-completion itself.
- `stopSessionTimer` (`delete(d.timers, npmPID)`) is called from exactly one
  place, `handleExit`. Grepped for other callers to be sure: none.

## Step 0b — confirm seams and the fix approach with the user

Four seams and the arbitration-primitive approach (`Session.MarkCompleteOnce`,
`sync.Once`-backed) were put to the user before any test was written, per the
TDD skill's requirement that no test be written at an unconfirmed seam. All
four confirmed; alternatives considered and rejected are in
[05-why-this-approach.md](05-why-this-approach.md).

## Slice 1 — `MarkCompleteOnce` itself

**Red:**

```
internal/session/session_test.go
441:15: session.MarkCompleteOnce undefined (type *Session has no field or method MarkCompleteOnce)
484:12: snap.State undefined (type Snapshot has no field or method State)
FAIL github.com/aniruddha/npm-ebpf-monitor/internal/session [build failed]
```

**Green:** added `completeOnce sync.Once` to `Session`, `State` to `Snapshot`,
and `MarkCompleteOnce` itself. All three tests pass on the first run after
implementation — this is expected for a from-scratch primitive being
test-driven directly, not a sign the tests are weak; slice 2 is what proves
the primitive actually closes the production race.

Raw: [`slice1-red.txt`](evidence/slice1-red.txt), [`slice1-green.txt`](evidence/slice1-green.txt).

## Slice 2 — the stress test, and the number that matters

**Red**, against `handleExit` and the timeout callback still calling
`session.Complete()` independently:

```
detector_test.go:613: session pid 20191 delivered on Completed() 2 times, want exactly 1
... (8 such lines)
detector_test.go:618: 8/300 sessions completed more than once
--- FAIL: TestDetectorNeverDeliversASessionMoreThanOnceWhenExitRacesTimeout (0.11s)
```

8 duplicates out of 300 trials on a single run — a real, repeatable defect
rate at this timeout width (1 microsecond), not a rare fluke requiring
extreme iteration counts to surface.

**Green:** wired both completion paths through `MarkCompleteOnce`, as in
[03-what-was-done.md](03-what-was-done.md). Re-ran the same 300-trial test:
0 duplicates, all 300 delivered exactly once. Re-ran it several more times
under normal `go test` to confirm this wasn't a one-off — no duplicate
observed across repeated runs.

Raw: [`slice2-red.txt`](evidence/slice2-red.txt), [`slice2-green.txt`](evidence/slice2-green.txt).

## Slice 3 — the timer leak, and its teeth check

The leak-cleanup line (moving `d.stopSessionTimer(npmPID)` to run
unconditionally in the timeout callback) was written as part of the same
change as slice 2's fix — both live inside the same callback body, so
`TestSessionTimeoutClearsItsOwnTimerEntry` passed the moment it was written,
without ever going red on its own.

**A guard that passes proves nothing until you know it can fail**, so it was
checked for teeth: temporarily removed just the
`d.stopSessionTimer(npmPID)` line (keeping the rest of the fix intact) and
re-ran:

```
detector_test.go:681: d.timers still holds an entry for pid 30000 500ms later
    (map has 1 total entries); the timeout callback never cleaned up its own entry
--- FAIL: TestSessionTimeoutClearsItsOwnTimerEntry
```

Confirmed genuine. The cleanup line was restored.

Raw: [`slice3-green.txt`](evidence/slice3-green.txt), [`slice3-teeth-check.txt`](evidence/slice3-teeth-check.txt).

## Slice 4 — the ordinary case, and the negative result

Built the ordinary-case regression test: a session with a comfortable 200ms
timeout, exiting almost instantly. It passed immediately.

Checked for teeth the same way as slice 3 — this time by reverting the entire
fix back to the pre-C3 `detector.go` (restoring the bare `session.Complete()`
calls with no arbitration) and re-running just this test:

```
=== slice 4 against the REVERTED (buggy) detector.go ===
--- PASS: TestDetectorTimedOutStaysFalseWhenExitCompletesBeforeTheTimer
PASS
```

Still passed, fully reverted. No teeth for C3 — the 200ms window and a
near-instant exit never create an actual race between the two paths, since
`stopSessionTimer` disarms the timer well before it could ever fire.

The fix was restored, the test relabelled with the negative result written
into its own doc comment (see slice 4 in
[02-tests.md](02-tests.md)), and slice 2 stands as the C3 regression test.

Raw: [`slice4-teeth-check.txt`](evidence/slice4-teeth-check.txt).

## Step 5 — verify the repository

```
$ go build ./...                                BUILD OK
$ go vet ./...                                  clean
$ go test ./internal/session/... -v -count=1    36 tests, all pass (full-session-suite.txt)
$ go test -race ./... -count=1                  all ok (9 packages)
$ sudo -n /usr/bin/go test ./... -count=1       all ok (9 packages)
```

Raw: [`full-session-suite.txt`](evidence/full-session-suite.txt),
[`race-suite.txt`](evidence/race-suite.txt), [`root-suite.txt`](evidence/root-suite.txt).
