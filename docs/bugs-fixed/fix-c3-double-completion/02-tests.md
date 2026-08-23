# 2. Tests

Six test functions across two packages, in four slices. The oracle for the
headline claim is a stress test at scale (300 independent sessions, exit
racing a 1-microsecond timeout) rather than the race detector alone — `-race`
flags unsynchronised memory access, but C3's bug is a logical double-send that
can happen even between two callers that each, individually, hold a lock
correctly. Both are used where they apply.

## Seams — agreed before any test was written

The TDD skill requires it ("No test is written at an unconfirmed seam"). Four
were proposed and **all four confirmed**, along with the choice of fix
(a `sync.Once`-backed arbitration method on `Session`, `MarkCompleteOnce`):

| Seam | Outcome |
|---|---|
| `MarkCompleteOnce` itself, under concurrent callers | ✅ **the tests with teeth** — unit-level, slice 1 |
| `Detector` end-to-end, exit racing timeout at scale | ✅ **the test with teeth** — 8/300 duplicates → 0, slice 2 |
| Timer-leak cleanup on the timeout path | ✅ covered, slice 3 |
| `TimedOut` stays correct for the ordinary non-racing case | ⚠️ **could not reproduce the race** — see below, slice 4 |

---

## Slice 1 — `TestMarkCompleteOnceHasExactlyOneWinner`, `TestMarkCompleteOnceSetsStateAtomicallyWithTimedOut`, `TestMarkCompleteOnceSecondCallDoesNotOverwriteTheFirstWinner`

Three tests against the new primitive directly, before it is ever wired into
the `Detector`.

The first is the defining property: 50 goroutines call `MarkCompleteOnce`
concurrently, alternating the `timedOut` argument, and exactly one must report
`won == true`. This is the property `sync.Once` gives for free, but the test
exists because the *reporting* of who won is new code, not `sync.Once`
itself.

The second constructs the exact disagreement the audit describes: normal exit
argues `timedOut=false`, a timeout callback moments later argues
`timedOut=true`. It asserts `TimedOut`, `State` and `EndTime` are all set
together by the winner, read back through `Snapshot()` rather than the raw
field — so this test also depends on C2's fix being in place, which it is.

The third is the sharpest one: call `MarkCompleteOnce(false)` (winner), then
`MarkCompleteOnce(true)` (loser), and assert `TimedOut` is still `false`
afterward. A naive implementation that gates the *send* but still lets a
losing call write fields would pass the first two tests and fail this one.

**Result: achieved.** Red (`session.MarkCompleteOnce undefined`, plus
`Snapshot.State undefined`) → all three pass.

Raw: [`slice1-red.txt`](evidence/slice1-red.txt), [`slice1-green.txt`](evidence/slice1-green.txt).

## Slice 2 — `TestDetectorNeverDeliversASessionMoreThanOnceWhenExitRacesTimeout`

**The test with teeth.** A real `Detector`, armed with a 1-microsecond
session timeout, runs 300 independent trials. Each trial submits an EXEC event
for a fresh PID immediately followed by an EXIT event for the same PID — with
a timeout that short, the timer is already armed and may fire before, during,
or after the exit is processed, so every trial is a genuine race between the
two completion paths, not a scripted one.

It drains `Completed()` into a `map[pid]count` and asserts every count is
exactly 1. It also guards against a false pass: it first asserts all 300
sessions were delivered *at all* (`len(deliveries) < trials` fails loudly)
before checking for duplicates, so a version of the fix that dropped sessions
instead of duplicating them could not pass silently.

**Result: achieved — this is the headline measurement.**

Before: **8 of 300 sessions delivered twice** — a real defect rate, not a
one-off flake. After: **0 duplicates, 300/300 delivered exactly once,** run
repeatedly.

Raw: [`slice2-red.txt`](evidence/slice2-red.txt), [`slice2-green.txt`](evidence/slice2-green.txt).

## Slice 3 — `TestSessionTimeoutClearsItsOwnTimerEntry`

Asserts the compounding leak is closed: a session that completes via timeout
must not leave an entry behind in `d.timers`. Reaches `detector.timers`
directly — unexported detector state with no public accessor — consistent
with how the rest of `detector_test.go` already configures unexported fields
like `cwdResolver`.

This is **a guard, not a fresh red**: the leak-cleanup line
(`d.stopSessionTimer(npmPID)` inside the timeout callback) was written as part
of the same change as the double-completion fix, so by the time this test was
written the code already passed it. Checked for teeth rather than trusted:
temporarily removing just that one line reproduces the leak and fails the
test.

```
detector_test.go:681: d.timers still holds an entry for pid 30000 500ms later
    (map has 1 total entries); the timeout callback never cleaned up its own entry
FAIL
```

**Result: achieved, and confirmed to have teeth.**

Raw: [`slice3-green.txt`](evidence/slice3-green.txt), [`slice3-teeth-check.txt`](evidence/slice3-teeth-check.txt).

## Slice 4 — `TestDetectorTimedOutStaysFalseWhenExitCompletesBeforeTheTimer` — **the seam that did not work**

Intended as the ordinary-case regression guard: a session with a 200ms
timeout exits almost instantly, so `TimedOut` must end up `false`, the session
must be delivered exactly once, and the armed timer must never fire.

It passed. Rather than accept that as C3 coverage, it was checked for teeth by
**reverting the fix** — restoring the pre-fix `detector.go` — and re-running:

```
=== slice 4 against the REVERTED (buggy) detector.go ===
--- PASS: TestDetectorTimedOutStaysFalseWhenExitCompletesBeforeTheTimer
PASS
```

**It still passed. The test has no teeth for C3.**

The reason is structural, not a flaw in the test's construction: with a
200ms window and an exit submitted essentially instantly, `stopSessionTimer`
cancels the timer well before it would ever fire — true whether or not
`MarkCompleteOnce`'s arbitration exists at all, since nothing here creates an
actual race between the two completion paths. Widening the window to
approach the real race would just turn this back into slice 2 with a slower,
less reliable timeout.

The test was **kept and relabelled rather than deleted**, with the negative
result written into its own doc comment. The property it was meant to cover —
"`TimedOut` reflects the actual winner" — genuinely is tested with teeth, just
at the unit level: slice 1's second and third tests construct the exact
disagreement and prove the winner's value survives. Slice 4 is kept as an
honest regression guard for the ordinary, non-racing case, not as C3 coverage.

Raw: [`slice4-teeth-check.txt`](evidence/slice4-teeth-check.txt).

---

## Goal coverage

| Goal | Covered by | Achieved |
|---|---|---|
| 1 — exactly one completion per session | Slice 2 (8/300 → 0/300 duplicates) | yes |
| 2 — `TimedOut` set safely and correctly | Slice 1 (unlocked write removed, loser cannot overwrite winner) | yes |
| 3 — timer leak closed | Slice 3 (teeth-checked) | yes |
| 4 — proven under real racing | Slice 2, at a scale (300 trials) that makes the defect rate measurable | yes |
| 5 — nothing else changes | full `-race` + root suites, all 9 packages | yes |
