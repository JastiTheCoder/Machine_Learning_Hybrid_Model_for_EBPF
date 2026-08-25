# 2. Test plan — H4

This is exactly the class of bug `CLAUDE.md` singles out: "For race conditions /
TOCTOU / timing-dependent bugs: a test that merely exercises the code path is
not sufficient... The test must reliably reproduce the vulnerable condition
(forced interleaving, repeated iterations, fault injection, etc.)." The
existing `TestRouter_UnknownPID` (`router_test.go:130`) already demonstrates the
drop *happens*; what's missing is a test that forces the specific interleaving
and proves it's fixed, not merely exercised.

## Seams to confirm with the user before writing any test

| Seam | Why this one |
|---|---|
| `Router.Run` fed by hand-controlled channels (as `TestRouter_UnknownPID`/`TestRouter_RaceConditions` already do) | The layer where the interleaving must be forced deterministically — real ring buffers can't be ordered on demand, so this seam is what makes "forced interleaving" possible at all, per `CLAUDE.md`'s own requirement |
| `Detector.RouteToSession` / the new pending-buffer (Plan 1) or the new ordering layer (Plan 2) directly | Where the fix actually lives |
| `Detector.DroppedRoutesForUnknownPID()` | The existing, already-correct observability this bug's fix must not regress, and the metric slice 3 below uses to prove the specific race is closed |

## Slice 1 — reproduce the drop deterministically (red, against current code)

**Test:** `TestRouterDoesNotPermanentlyDropASyscallEventThatArrivesBeforeItsEXEC`
(or similar), added to `internal/session/router_test.go`, following the existing
`TestRouter_UnknownPID` pattern of feeding hand-built channels directly (not a
real ring buffer) so the interleaving is forced, not hoped for:

```go
procCh := make(chan collector.ProcessEvent, 1)
sysCh := make(chan collector.SyscallEvent, 1)
detector := session.NewDetector(0)
router := session.NewRouter(detector, procCh, sysCh, nil, nil, nil)

// Force the disfavored order: syscall event lands first, EXEC follows.
sysCh <- collector.SyscallEvent{Pid: 4242, SyscallID: someID}
go router.Run(ctx)
// give the router a chance to process sysCh's event before procCh even has one
time.Sleep(smallDelay)
procCh <- collector.ProcessEvent{Pid: 4242, EventType: exec, ... /* npm install shape */}

// ... wait for the session to register (poll or a done-channel) ...
sess := /* look up the session for pid 4242 */
if /* the syscall event never reached the session's counters */ {
    t.Error("syscall event delivered before its EXEC was permanently lost")
}
```

The exact assertion depends on the chosen fix's observable contract (buffered-
and-replayed vs. ordered-upstream), so the precise "did it survive" check
should be written against whichever plan is picked — but the *setup* (forced
disfavored interleaving via hand-fed channels, a small deterministic delay or
explicit synchronization to guarantee the syscall event is read first) is
plan-agnostic and should be written first, before deciding the exact assertion.

**Expected before any fix:** **red** — the syscall event is dropped
(`DroppedRoutesForUnknownPID()` increments by 1, and the eventual session's
syscall counters do not reflect it).

## Slice 2 — repeated trials, not a single lucky/unlucky run

Per `CLAUDE.md`'s "repeated iterations" requirement: wrap slice 1's core in a
loop of at least 100-300 independent trials (matching the scale
`docs/bugs-fixed/fix-c3-double-completion` already used for a comparable race,
"300 independent sessions"), each with a fresh PID and fresh detector/router
pair, asserting **zero** drops across all trials after the fix — a single-trial
pass is not sufficient evidence for a race-shaped bug per this project's own
standard.

**Expected before any fix:** red on a nonzero fraction of trials (the exact rate
is itself worth recording as evidence, the way C3's fix documented "8 of 300").
**Expected after the fix:** 0 drops across all trials, run repeatedly (at least
twice) to rule out a flake in the fix itself.

## Slice 3 — the buffer/ordering mechanism has a bound (Plan 1 only)

If Plan 1 (pending-event buffer) is chosen: a dedicated test proving the buffer
cannot grow unboundedly — feed syscall/file/TCP events for many distinct PIDs
that *never* get a matching EXEC, at a volume exceeding the chosen cap, and
assert (a) the detector doesn't grow memory unboundedly (e.g. assert
`len()`/a size accessor stays at or below the configured cap) and (b) events
beyond the TTL are dropped and counted via the existing
`DroppedRoutesForUnknownPID`, not silently retained forever.

**Expected before any fix:** not applicable (the buffer doesn't exist yet) —
this slice only exists under Plan 1 and should be written red-then-green against
the new buffer code itself, immediately after slice 1/2 establish the buffer's
core replay behavior.

## Slice 4 — no regression to existing router/detector coverage

Run the full existing suite, with focus on:

- `TestRouter_Multiplexing`, `TestRouter_ContextCancellation`,
  `TestRouter_UnknownPID`, `TestRouter_RaceConditions` (`router_test.go`) — all
  must stay green.
- Full `internal/session` package under `-race`.
- The root-gated regression suite (`cmd/monitor/e2e_regression_test.go`) if the
  fix touches anything `cmd/monitor` wires together — likely not, since this is
  scoped to `internal/session`, but worth confirming rather than assuming.

## eBPF/kernel-specific test notes (per `CLAUDE.md`)

Plan 1 and Plan 3 are pure Go, entirely testable at the unit/integration level
with **no root/CAP_BPF required** — the interleaving is forced via hand-fed
Go channels, never real ring buffers, so no kernel load/run is involved and no
environment limitation applies. Plan 2, if it reaches into collector or BPF
changes (its kernel-side variant), would require root/CAP_BPF and a real kernel
load to verify the ordering guarantee end-to-end — flagged explicitly here so
whoever picks Plan 2 knows to state that distinction in their own test-plan
update, per this project's standing convention.

## Teeth-check plan

Slice 1/2 is the reproduction (red by construction) and the primary
teeth-check simultaneously — a race test that has never actually failed on the
broken version proves nothing about the fixed one, per this project's own
established practice (see `docs/bugs-fixed/fix-c3-double-completion`'s "two
guards checked for teeth" precedent). After implementing, additionally: revert
just the fix's core mechanism (the buffer or the ordering change) and re-run
slice 2's repeated-trial loop, confirming it reproduces a nonzero drop rate
again — proving the fix, not an unrelated change, is what closes it.

## Goal coverage

| Goal (from `01-bug.md`'s Expected result) | Covered by |
|---|---|
| Forced disfavored-order event is no longer permanently dropped | Slices 1, 2 |
| Bound/TTL holds under sustained unmatched traffic (Plan 1) | Slice 3 |
| No regression | Slice 4 |
| Fix is real, not coincidental | Teeth-check (revert, confirm red rate returns) |
