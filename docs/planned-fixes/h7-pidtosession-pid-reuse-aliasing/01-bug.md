# 1. Bug — H7: `pidToSession` has no generation guard against PID reuse

Source finding: `AUDIT.md` H7, re-verified still open in
[`../../NEW_AUDIT.md`](../../NEW_AUDIT.md#re-verified-against-auditmd-not-copied).

## How it came about

`pidToSession map[uint32]*Session` (`internal/session/detector.go:28`) was
introduced in commit `8ac3f5f` (2026-04-03), the same commit that first
productionized the collector→router→detector pipeline, as a plain PID-keyed map
with no generation or epoch guard — an original design gap, not a later
regression. `handleExec` (`detector.go:185-254`) and `associatePID`/`trackPID`
(`detector.go:364-376`) look sessions up purely by PID number.

The exposure mechanism, per `NEW_AUDIT.md`'s re-verification: H5's now-fixed
"silent drop" finding means an EXIT event *can* still be dropped under real
backpressure (now counted, but not prevented — see each collector's
`DroppedEvents()`), and `untrackPID` (`detector.go:386-390`) — the only place
that removes a `pidToSession` entry for a non-root child PID — is only ever
called from `handleExit` (`detector.go:271-315`), which never runs if that PID's
own EXIT event was among the dropped ones. If the OS then reuses that PID
number for a brand-new, unrelated `npm install` before the stale entry is ever
cleaned up (which, absent an EXIT event ever arriving for it, may be never,
short of the *session's own* eventual timeout or completion via its other
PIDs), `handleExec` finds the stale session and folds the new install's events
into it.

This is, per the verdict-engine feature's own
`docs/new-features/001-verdict-scoring-engine/07-findings-not-fixed.md`
("finding A"), the leading *unconfirmed* explanation for a previously-observed,
still-unexplained case of one fixture's captured evidence not matching anything
that fixture itself did — ruled out there as "naive trace-everything, filter-
later" (kernel-side `is_tracked` filtering was confirmed correct), leaving
userspace PID-reuse aliasing as the most plausible remaining mechanism, not
proven. This bug's fix should aim to close the mechanism, and — if a targeted
reproduction succeeds — may also resolve that longstanding open question, though
confirming that specific historical case is not required for this bug to be
considered fixed on its own terms.

## Candidate fixes

### Plan 1 (recommended) — generation counter per PID slot

Change `pidToSession` from `map[uint32]*Session` to a small wrapper,
`map[uint32]pidSlot{session *Session; generation uint64}` (naming indicative,
not prescriptive). Every time a PID is (re)registered — in `registerSession`,
`trackPID`, and `associatePID` — increment that PID's generation. `handleExec`'s
reuse check (currently: "does `sessionForPID(event.Pid)` or
`sessionForPID(event.Ppid)` return a session?") gains an explicit guard: if an
existing `pidToSession` entry's session is already `SessionComplete`
(`Session.State`, readable via a small new accessor or `Snapshot().State`), do
not fold the new EXEC into it — treat the PID as unregistered and proceed to
the normal "is this an npm install invocation" path, registering a fresh
session instead. `RouteToSession` needs no change: it already holds the
session pointer directly once looked up, so a stale pointer is exactly the bug
(routing into a session that should have been superseded); the generation
check belongs at the point a PID is *reused for a new registration*, not at
every route.

- **Cost:** touches `pidToSession`'s type and every read/write site
  (`registerSession`, `unregisterSession`, `trackPID`, `associatePID`,
  `untrackPID`, `sessionForPID`) — a moderate, mechanical diff, not a
  conceptually large one.
- **Why recommended:** closes the actual aliasing mechanism directly: a
  completed session's stale PID mapping can never again be treated as live,
  regardless of whether its EXIT event was ever delivered.

### Plan 2 — shrink the exposure window instead of adding an epoch

Audit every code path that can leave a PID live in `pidToSession` after its
process has actually exited, and make `untrackPID` fire synchronously and
unconditionally on exit rather than depending on `remaining == 0` bookkeeping
or a delivered EXIT event alone — e.g. have the session timeout path (which
already runs regardless of missing EXIT events) also sweep and untrack any PID
in its `LivePIDs` set whose `/proc/<pid>` no longer exists, as an additional
safety net alongside the EXIT-driven path.

- **Cost:** smaller than Plan 1's type change, but doesn't eliminate the race —
  only shrinks the window a PID can be reused within, which is a mitigation,
  not a fix, and is harder to reason about/prove a bound on ("how small is
  small enough" is not a falsifiable claim the way "can never happen" is).
- **When this might be preferred:** if Plan 1's mechanical diff across every
  `pidToSession` call site is judged too large for one session, this is a
  legitimate, smaller first step — but should be clearly labeled a mitigation,
  not a fix, if chosen instead of Plan 1.

## Expected result

- A targeted, forced reproduction — not reliance on real OS PID-recycling
  timing, per `CLAUDE.md`'s own standard for this class of bug — demonstrates
  that once a session is complete, its former PIDs can no longer have a new,
  unrelated session's events folded into it: force PID `N`'s session to
  complete (e.g. via the existing test-only PID injection patterns already used
  in `detector_test.go`), then submit a fresh EXEC event for the same PID `N`
  and assert a **new**, distinct session is created rather than the old one's
  evidence/counters being extended.
- The existing, still-unexplained evidence-misattribution observation
  referenced in `docs/new-features/001-verdict-scoring-engine/07-findings-not-fixed.md`
  is either newly reproducible via this same mechanism (worth noting as
  resolved, with evidence) or remains genuinely unexplained by it — either
  outcome is an acceptable result for *this* bug, but the fix's own test must
  not claim to have resolved that historical case without direct reproduction.
- No regression: `TestDetector_NpmInstallLifecycle`, PID-reuse-adjacent existing
  tests, and the full `internal/session` suite (including `-race`) stay green.
