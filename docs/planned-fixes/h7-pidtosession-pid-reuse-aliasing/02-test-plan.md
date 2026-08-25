# 2. Test plan — H7

Per `CLAUDE.md`'s own standard for this class of bug: *"the test must reliably
reproduce the vulnerable condition (forced interleaving, repeated iterations,
fault injection, etc.) — 'test passes' must mean the race is actually closed,
not just untriggered on that run."* Real OS PID recycling cannot be forced
deterministically in a unit test, so the reproduction must force the condition
structurally — completing a session, then directly submitting a fresh EXEC for
the same PID number — rather than waiting on or simulating kernel PID-allocator
timing.

## Seams to confirm with the user before writing any test

| Seam | Why this one |
|---|---|
| `Detector.HandleProcess` fed EXEC/EXIT events directly (the same seam `detector_test.go` already tests through) | Lets the reproduction force "PID N's session completes, then PID N gets a brand-new EXEC" without needing a real process or real PID recycling |
| `Detector`'s session registry, read via existing test-accessible state (however `detector_test.go` currently inspects `activeSessions`/`pidToSession` — reuse that pattern, don't invent a new accessor if one already exists) | Where the fix's core guarantee ("a completed session's PID can't be reused for it") is actually checked |
| `RouteToSession` post-reuse | Confirms events for the *new* session's PID land in the *new* session, not bleed into the old, completed one — the actual harm this bug describes |

## Slice 1 — reproduce the aliasing (red, against current code)

**Test:** `TestHandleExecDoesNotReuseACompletedSessionsStalePID` (or similar),
added to `internal/session/detector_test.go`, following the existing package's
pattern of driving `Detector` directly with hand-built events (as
`TestDetector_NpmInstallLifecycle` and siblings already do).

```go
d := session.NewDetector(0)
const reusedPID = 50000

// First install: PID 50000 becomes an npm root, then completes normally.
d.HandleProcess(execEvent(reusedPID, 0, "npm install first-pkg"))
d.HandleProcess(exitEvent(reusedPID))
first := <-d.Completed()

// Simulate the OS handing PID 50000 to a brand-new, unrelated npm install
// before any cleanup-adjacent timer/GC has a reason to run.
d.HandleProcess(execEvent(reusedPID, 0, "npm install second-pkg"))
d.RouteToSession(reusedPID, func(s *session.Session) { s.AddSyscall(someSyscallEvent) })

// The syscall must land in a *second*, distinct session -- never in `first`,
// which is already complete and should be immutable at this point.
if syscallLandedIn(first, someSyscallEvent) {
    t.Error("event for a reused PID was folded into the original, " +
        "already-completed session instead of a new one")
}
```

The exact mechanics of "simulate the OS handing the PID to a new install"
depend on which internal path is exercised (`handleExec`'s reuse check
directly, vs. going through the full `HandleProcess` dispatch) — write it
against `HandleProcess` first, since that's the real production entry point,
matching this project's existing preference (established during the H3 fix) for
testing the actual call path production uses.

**Expected before any fix:** **red** — either the second `HandleProcess` call
silently no-ops (treating PID 50000 as already tracked, per `handleExec`'s
existing `d.sessionForPID(event.Pid) != nil` short-circuit,
`detector.go:186-190`) and the subsequent `RouteToSession` folds the syscall
into `first`, or (depending on exact current behavior once traced during
implementation) some other incorrect outcome — either way, the assertion that a
*new* session was created and received the event must fail against current
code. Confirm and record the exact current failure mode as evidence before
writing the fix.

## Slice 2 — a genuinely new session is created, and it's usable

**Test:** extend slice 1 (or add a sibling assertion) to confirm the *positive*
side, not just the negative: after the reuse, a second, distinct `Session`
exists, has its own fresh `ID`/`PackageName`/`SyscallCounts`, and correctly
receives subsequent events routed to `reusedPID`.

**Expected before any fix:** depends on the exact current failure mode found in
slice 1 (may already partially "work" by accident, e.g. if the reuse check
happens to fall through to registering a new session in some paths — this
needs to be traced, not assumed, during implementation). Regardless, this slice
must be green after the fix, proving the fix produces correct *positive*
behavior, not just suppresses the *negative* one.

## Slice 3 — an in-progress (not yet complete) session's PID is unaffected

**Test:** a companion, explicitly-not-buggy case: a PID belonging to a session
that has **not** completed must continue to be treated as live and routed to
normally — i.e., the fix must not accidentally make `handleExec` treat every
repeat EXEC for an active session's PID as "reuse." Construct a session, submit
a second EXEC for the *same, still-active* PID, and assert the original session
is unaffected (matching `attachExec`'s existing dedupe behavior,
`detector.go:335-341`, which already guards against re-adding the npm root PID
or an already-known child PID to its own process tree).

**Expected before any fix:** already green (this is existing, correct
behavior) — run once as a baseline, then re-confirm green after the fix, so the
fix's generation/completion check doesn't regress the ordinary case.

## Slice 4 — bound/no regression under repeated reuse

Per "repeated iterations": loop slice 1's core scenario across many distinct
simulated reuse cycles (e.g. 100+, reusing a small set of PID numbers across
many sequential complete→reuse pairs) asserting zero aliasing across all of
them — the equivalent rigor `docs/bugs-fixed/fix-c3-double-completion` applied
at 300 trials for a comparable "prove it under real racing, not by reasoning
about the code" bar, adapted here to repeated structural reuse rather than
timing-based racing (since H7, unlike C3, is not fundamentally a goroutine
race — it's a state-correctness bug that a single well-constructed
reproduction already demonstrates deterministically; the repetition here is
about confidence and catching any off-by-one/edge-case in the generation
bookkeeping, not about surfacing a flaky interleaving).

## eBPF/kernel-specific test notes (per `CLAUDE.md`)

This bug's fix and all four slices above are pure Go, testable entirely at the
`Detector` seam with **no root/CAP_BPF required** and no kernel load/run — PID
reuse is forced structurally (complete a session, then submit a new EXEC for
the same PID number), never by waiting on or provoking real OS PID-allocator
behavior. If the historical evidence-misattribution case (referenced in
`01-bug.md`'s Expected result) is separately investigated as a stretch goal, that
investigation would need a real, root-gated capture to attempt reproduction
against actual kernel PID recycling — but that is explicitly not required for
this bug's own fix to be considered complete, per `01-bug.md`.

## Teeth-check plan

Slice 1 is the reproduction (red by construction against current code) and
doubles as the primary teeth-check. After implementing the fix, additionally:
revert only the new generation/completion-check logic (not the whole change)
and re-run slice 1 and slice 4, confirming both reproduce the aliasing again —
ruling out the fix passing for a reason unrelated to the actual guard.

## Goal coverage

| Goal (from `01-bug.md`'s Expected result) | Covered by |
|---|---|
| A completed session's PID can't be reused into it by a later EXEC | Slices 1, 2, 4 |
| Ordinary (non-reuse) repeat-EXEC behavior unaffected | Slice 3 |
| Fix holds under repetition, not just one lucky construction | Slice 4 |
| Fix is real, not coincidental | Teeth-check (revert, confirm red again) |
