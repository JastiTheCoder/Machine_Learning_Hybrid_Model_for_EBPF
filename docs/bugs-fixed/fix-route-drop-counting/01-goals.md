# 1. Goals

## The defect

`AUDIT.md` H4, verbatim:

> `context/architecture.md` states that process events are given priority in
> the router's outer `select` specifically to prevent syscall events for a
> brand-new PID from being dropped before its session exists. The actual
> mechanism only prefers `procCh` if a message is *already buffered* on it at
> select time; if not, the inner `select` treats all five channels equally
> (no priority). More fundamentally, the five event types arrive via five
> *independent* ring-buffer-reading goroutines, so there is no cross-channel
> delivery-order guarantee at all regardless of the select structure — a
> syscall event for a brand-new PID can physically be read and channeled
> before the corresponding EXEC event. When that happens, `RouteToSession`
> finds no session for that PID and silently, permanently drops the event (no
> retry, no counter, no log by default). The priority pattern lowers the odds
> of this; it does not eliminate the race the docs say it eliminates.

Verified by reading, not assumed:

- `context/architecture.md:317` (pre-fix) states exactly the false guarantee
  the audit describes: *"Without priority, syscall events for a brand-new PID
  would be silently dropped... [priority prevents this]."*
- `Router.Run`'s outer `select` (`router.go`) only takes the `procCh` case
  ahead of the others when `select`'s own non-deterministic scheduling
  happens to have a value already waiting on `procCh` at that instant — Go's
  `select` with a `default` case does not poll or wait, it checks once.
- `RouteToSession` (`detector.go`, pre-fix): `if session == nil { return }` —
  confirmed to be the exact, sole drop point the audit describes, with
  literally zero counter, log, or retry of any kind.
- The five collectors (`process_collector.go`, `syscall_collector.go`,
  `file_collector.go`, `tcp_collector.go`, `bytes_collector.go`) each run
  their own independent `Run(ctx)` goroutine reading their own ring buffer —
  confirmed there is no shared sequencing mechanism across them at all, so
  the audit's "no cross-channel delivery-order guarantee" is architectural,
  not a bug introduced by any one file.

## Why full elimination is out of scope for this fix

Truly eliminating the race would mean either merging all five event streams
into one globally-ordered stream (each event already carries a
`bpf_ktime_get_ns()` timestamp, so a timestamp-based reorder buffer is
possible in principle) or holding and retrying events for unrecognized PIDs
until their session registers. Both are real architectural changes — a new
buffering/merge subsystem, added latency on every event, new failure modes of
their own — disproportionate to what the audit asks for and inconsistent
with this project's established pattern of narrow, defensive fixes (see H2's
decision to count `pending_opens` insert failures rather than redesign the
map). The audit's own wording treats the race as inherent ("no cross-channel
delivery-order guarantee at all regardless of the select structure"), not as
something a `Router`-level fix could close.

## Goals

1. **Correct the false documentation claim** in `context/architecture.md` —
   the priority pattern narrows the race, it does not eliminate it.
2. **The drop is counted**, closing "no counter."
3. **The drop is logged when verbose logging is enabled**, closing "no log by
   default" — the "by default" wording implies a non-default (verbose) mode
   should log it.
4. **`cmd/monitor` reports a nonzero drop count at shutdown**, matching the
   existing `LOST N of M session(s)` / `pending_opens` insert-failure
   reporting shape.
5. **Nothing else changes** — no reordering, no retry buffer, no change to
   `Router`'s select structure, no change to any `handle*` method's logic.

## How we would know

- Goal 1 → the corrected paragraph in `context/architecture.md`, stating the
  true (narrowed-not-eliminated) guarantee.
- Goals 2–3 → a unit test calling `RouteToSession` directly for an unknown
  PID, asserting the counter increments and a configured verbose logger
  receives a line — plus a negative check that a *known* PID does neither.
- Goal 4 → the existing `TestRouter_UnknownPID` test, extended with a count
  assertion, proving the counter increments through the real `Router` path,
  not just a direct call.
- Goal 5 → full repository suite, `-race` and under root; `router.go` itself
  is untouched.
