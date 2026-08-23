# 1. Goals

## The defect

`AUDIT.md` C3, and its compounding leak note, verbatim in substance:

> `handleExit` and the `time.AfterFunc` timeout callback are two independent
> completion paths running on different goroutines — the router goroutine and
> the Go runtime's timer goroutine — and neither checks whether the other has
> already completed the session. […] gated only by `completedMu.RLock()` —
> which prevents a send after the channel is closed, but not a double-send
> between the two paths, since both only ever take the read side of that
> RWMutex simultaneously. […] the timeout callback also never calls
> `stopSessionTimer` / `delete(d.timers, npmPID)` on itself — only the
> normal-exit path does. Every session that completes via timeout leaves its
> `*time.Timer` entry in `d.timers` permanently.

Verified by reading, not assumed:

- `handleExit` (`detector.go:292`): once `remaining == 0`, calls
  `stopSessionTimer`, `session.Complete()`, `unregisterSession`, then
  `d.completedSessions <- session`.
- The timeout callback inside `startSessionTimer` (`detector.go:417`): sets
  `s.TimedOut = true` **with no lock at all**, calls `s.Complete()`, checks
  `d.completedMu.RLock()` / `completedClosed`, then independently does
  `unregisterSession` + `d.completedSessions <- s`.
- `HandleProcess` (the dispatch loop's entry point, which calls `handleExit`)
  takes `d.completedMu.RLock()` around the whole call. The timeout callback
  takes its own `d.completedMu.RLock()`. `RWMutex` allows any number of
  concurrent readers — so both paths can hold the read lock **simultaneously**,
  which is exactly the audit's claim and exactly why nothing here provides
  mutual exclusion between them.

Two more things came directly from reading the code, not the audit prose:

- `s.TimedOut = true` is a bare field write, outside `s.mu`. Any locked reader
  (post-C2, that means every read via `Snapshot()`) still races it, because Go's
  race model does not exempt a write just because the *other* side happens to
  hold a lock.
- The leak is real and unconditional: `stopSessionTimer` is the only code path
  that ever does `delete(d.timers, npmPID)`, and it is called from exactly one
  place — `handleExit`. A session that completes via timeout never reaches
  that call.

## Why this is the last Critical finding, and why now

C1, C2 and C4 are fixed. C3 is the remaining one, and like C2 it is a
concurrency bug: real only under a specific interleaving, invisible in an
ordinary test run, and directly relevant to running a long, high-throughput
capture — the very next planned step for this project.

## Goals

1. **Exactly one completion per session.** Whichever path notices first, the
   other must become a no-op — no duplicate `BuildRecord`/`Write`, no duplicate
   delivery on `Completed()`.
2. **`TimedOut` must be set safely and correctly.** No unlocked writes; the
   value must reflect whichever path actually won, not be overwritten by the
   loser.
3. **The timer leak is closed.** A session that completes via timeout must not
   leave a `d.timers` entry behind.
4. **Prove it under real racing, not by reasoning about the code.** A stress
   test that forces the two paths to race, at a scale that makes an 8-in-300
   defect rate visible rather than lucky.
5. **Nothing else changes** — no BPF, no schema, no output format.

## How we would know

- Goal 1 → a Detector-level stress test racing exit against timeout across many
  independent sessions, asserting no session is ever delivered more than once.
- Goal 2 → unit tests on the new arbitration primitive itself, constructing the
  exact disagreement (a losing call arguing for the opposite `TimedOut` value)
  and proving the winner's value survives.
- Goal 3 → a same-package test reaching `d.timers` directly after a timeout
  completion.
- Goal 4 → the stress test's trial count and repeated runs; guards checked for
  teeth by reverting the relevant code.
- Goal 5 → full repository suite, `-race` and under root.
