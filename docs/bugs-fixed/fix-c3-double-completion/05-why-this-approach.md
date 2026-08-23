# 5. Why this approach

## Why a `sync.Once`-backed method rather than a checked flag

The obvious-looking alternative is a boolean on `Session` — `if s.completed
{ return false }; s.completed = true` — guarded by `s.mu`. It was rejected as
strictly more code for the same guarantee `sync.Once` already gives.

`sync.Once.Do` provides two things a hand-rolled flag needs a lock spanning
*both* the check and the set to reproduce correctly: exactly-once execution of
the winning body, and every other caller blocking until that body has
finished (rather than racing ahead believing they lost before the winner has
actually recorded anything). Getting the second property right by hand means
taking `s.mu` around the entire check-and-set, at which point the "flag"
approach *is* `sync.Once` in slower, more error-prone form. Using the standard
library primitive directly removes an entire class of "did I get the lock
scope right" bugs from review.

## Why the arbitration lives on `Session`, not on `Detector`

`Detector` could instead track "have I already sent this session" itself —
e.g. a `map[uint32]bool` of completed PIDs guarded by `d.mu`. Rejected for two
reasons:

1. **It re-derives state the `Session` already owns.** `Session.State` already
   distinguishes complete from not-complete; a second, parallel piece of
   completed-tracking on `Detector` is a second place that discipline can be
   forgotten in future code, which is exactly the shape of bug C2 and C3 both
   are.
2. **It does not fix the unlocked `TimedOut` write.** That bug is entirely
   inside `Session` — a `Detector`-side completed-set would stop the duplicate
   send but do nothing about the bare `s.TimedOut = true` outside any lock,
   leaving a real data race in place under `-race`.

Putting `MarkCompleteOnce` on `Session` means the object that owns the state
being raced also owns the only correct way to transition it — the same shape
`Snapshot()` established for C2: a method that cannot be called incorrectly,
rather than a lock or a flag that must be remembered by every caller.

## Why the timer-leak fix moves the cleanup call, not adds a new one

The alternative considered was leaving `d.stopSessionTimer(npmPID)` where it
was (only in `handleExit`) and adding a *second*, separate cleanup call inside
the timeout callback, gated on `MarkCompleteOnce`'s result. Rejected: the leak
exists specifically because the timeout callback is the *only* code path that
runs when a session times out, so its own cleanup must not be conditional on
winning the completion race — a losing timeout callback still has a live
`d.timers` entry that only it can remove, since `handleExit` for the same
session already ran (or is running) its own `stopSessionTimer` for the same
key, which is harmlessly idempotent. Running `stopSessionTimer` unconditionally,
before the win/lose branch, is simpler than adding a second conditional path
and closes the leak regardless of which side wins.

## Why the stress test uses a 1-microsecond timeout, not a longer one

A realistic session timeout (the codebase defaults to well over a second) would
make the race window vanishingly rare to hit from outside — exactly the
"invisible in an ordinary test run" property that let C3 ship in the first
place. Setting `sessionTimeout` to 1 microsecond guarantees the timer is
already armed and racing against the EXIT event's processing on every single
trial, without needing an implausible number of iterations to find the
interleaving by chance. This mirrors the same tension C2's fix navigated with
`-race`: the oracle has to be one that can actually observe the defect, not
merely one that theoretically could.

## Why the failed seam (slice 4) was kept and relabelled rather than deleted

Slice 4 does not reproduce C3 — proven by reverting the entire fix and
watching it still pass. The same two options as C2's slice 3: delete it, or
keep it with the truth attached.

It was kept because it is the only test exercising the ordinary,
non-competing timeout path end-to-end through the `Detector` — real coverage
of real wiring, just not of this bug. What would have been dishonest is a
comment claiming it covers C3's race; a future reader trusting that claim
could mistake it for regression coverage it does not provide, and might
delete slice 2 as redundant. The comment states the negative result and names
slice 2 as the test with teeth, matching the discipline already established
in [`../fix-c2-buildrecord-race/05-why-this-approach.md`](../fix-c2-buildrecord-race/05-why-this-approach.md).

## Why both teeth checks were run at all

Slices 3 and 4 both passed on their first run. The tempting reading each time
is "the fix works, confirmed" — and for slice 4 that reading would have been
wrong. Reverting the relevant code and re-running cost a few minutes each and
converted an assumption into a measured fact for both: slice 3's teeth were
genuine, slice 4's were not. Skipping either check would have let a vacuous
guard stand undetected, or let a genuine one go unverified — the same
discipline as C2's slice 3 and C4's labeller re-derivation.
