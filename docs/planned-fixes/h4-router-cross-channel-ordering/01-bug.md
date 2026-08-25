# 1. Bug — H4: router priority doesn't guarantee cross-stream ordering

Source finding: `AUDIT.md` H4, re-verified still open in
[`../../NEW_AUDIT.md`](../../NEW_AUDIT.md#re-verified-against-auditmd-not-copied).

## How it came about

`internal/session/router.go` was introduced whole in commit `8ac3f5f` ("feat:
add CSV export utility and ML handoff docs", 2026-04-03) — the same commit that
first productionized the collector→router→detector pipeline. This predates
`AUDIT.md` itself (first written 2026-08-22); it is an original design choice,
not a regression introduced by a later fix.

`Router.Run` (`router.go:40-106`) reads five independent channels
(`procCh`, `sysCh`, `fileCh`, `tcpCh`, `bytesCh`) — each fed by its own
goroutine reading its own BPF ring buffer — through a nested `select`: an outer
`select` checks only `ctx.Done()` and `procCh` with a `default:` fallthrough,
then an inner `select` treats all five channels with no priority among them.
`context/architecture.md` (predating this bug's own documentation) describes
this shape as existing specifically "to prevent syscall events for a brand-new
PID from being dropped before its session exists" — but the outer select's
`procCh` case only fires when a process event is *already buffered* at the
exact moment `select` runs; if it isn't, the inner select treats `procCh`
identically to the other four. More fundamentally, since the five event types
are read by five *independent* goroutines with no shared sequencing, no
select-based prioritization on the consuming side can guarantee a syscall/file/
TCP event for a brand-new PID is never read and routed before the corresponding
EXEC event — the race exists between the producer goroutines, not just in how
the router chooses among already-arrived events.

`Detector.RouteToSession` (`detector.go:127-150`) silently dropped such
orphaned events entirely until commit `65b3d8e` ("Fix H4: count and log
RouteToSession drops for unknown PIDs", 2026-08-23) added
`DroppedRoutesForUnknownPID`/verbose logging — a real, if partial,
improvement (the drop is no longer invisible) that does not close the
underlying race.

## Candidate fixes

### Plan 1 (recommended) — bounded per-PID pending-event buffer in `Detector`

When `RouteToSession` finds no session registered for a PID, instead of
dropping the event immediately, hold it in a small, bounded, per-PID buffer
(e.g. `map[uint32][]pendingEvent`, capped at a handful of entries and a short
TTL — both need concrete values chosen during implementation, informed by real
event-volume data already in this project's evidence, e.g. "a single `lodash`
install generates roughly 13,000 syscall events"). When a matching EXEC event
later registers the PID, replay the buffered events into the new session before
processing anything else for that session. Expire and drop (counting the drop,
as today) anything that ages out unmatched.

- **Cost:** new state in `Detector`, a bound to choose and justify, and care
  around ordering (buffered events must replay in original arrival order, and
  must not be replayed twice if two are buffered for the same PID before the
  EXEC arrives).
- **Risk:** must not become unbounded under a PID that legitimately is not
  npm-related noise (if any ever reaches the router despite kernel-side
  `is_tracked` filtering) — the cap and TTL are what keep this safe; this needs
  its own test proving the bound holds under sustained bogus traffic.
- **Why recommended:** closes the actual race (an event for a not-yet-registered
  PID is no longer lost, only delayed) rather than narrowing the window it
  occurs in, and stays scoped to `internal/session` — no kernel or collector
  changes required.

### Plan 2 — establish ordering upstream of the router

Restructure event delivery so cross-type ordering is established before the
router ever sees events — e.g. a single funnel goroutine per event type
tagging a monotonic sequence number as events are read from their ring
buffers, feeding one ordered channel the router drains in strict order; or,
more invasively, consolidating the four separate kernel ring buffers into one
shared ring buffer in BPF so the kernel itself establishes a single total
order at emission time.

- **Cost:** significantly larger — touches every collector (for the
  sequence-number variant) or the kernel programs themselves (for the shared-
  ring-buffer variant), well outside this project's usual one-finding-per-
  session change size, and outside this repo's established pattern of scoping
  eBPF/kernel changes tightly (per `CLAUDE.md`'s own instruction: "Fix ONLY the
  vulnerability specified... do not fix, refactor, or touch other unfixed
  AUDIT.md items in this session").
- **Benefit:** likely the architecturally "correct" long-term answer — true
  ordering, not a buffer-and-hope mitigation.
- **Recommendation:** flag as a follow-up finding for its own, separate,
  larger-scoped session rather than attempt within this bug's fix; listed here
  for completeness since the plan explicitly allows proposing more than two
  approaches.

### Plan 3 (smaller, partial — fallback if 1 proves too large for one session)

Leave the race itself unaddressed, but sharpen `RouteToSession`'s existing drop
counter to distinguish "PID never appeared at all" from "PID's EXEC arrived
moments later, just too late" — e.g. via a short-lived recently-seen-PID set
(`map[uint32]time.Time`, pruned periodically) checked when logging a drop.

- **Cost:** small.
- **Benefit:** does not fix anything, only sharpens the existing H4 diagnostics
  from "N events dropped for unknown PIDs" to "N events dropped, of which M were
  for a PID that registered within Xms afterward" — valuable operational
  visibility into how often the race actually bites in practice, which could
  also inform whether Plan 1's buffer bound is actually needed at all.
- **Positioning:** a legitimate first slice even under Plan 1 (the visibility
  it adds is useful evidence for sizing the buffer/TTL), not only a standalone
  fallback.

## Expected result

- A deliberately forced interleaving — an EXEC event for a brand-new PID
  delivered to the router *after* a syscall/file/TCP event for that same PID
  (the disfavored order relative to the outer select's `procCh` preference) — no
  longer results in the non-proc event being permanently dropped. Under Plan 1:
  the event is buffered and replayed once the session registers. Under Plan 2:
  ordering is established before the router observes the events at all.
- `DroppedRoutesForUnknownPID()` no longer increments for this specific,
  reproducible interleaving (it may still increment for genuinely unmatched
  PIDs, e.g. ones that never get an EXEC at all within the bound/TTL — that is
  expected and correct).
- No regression to existing router/detector behavior: `TestRouter_RaceConditions`
  and the full `detector_test.go`/`router_test.go` suites stay green, including
  under `-race`.
