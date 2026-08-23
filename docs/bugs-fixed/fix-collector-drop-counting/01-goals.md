# 1. Goals

## The defect

`AUDIT.md` H5, verbatim:

> All five collectors (`process_collector.go`, `syscall_collector.go`,
> `file_collector.go`, `tcp_collector.go`, `bytes_collector.go`) use the same
> pattern:
>
> ```go
> select {
> case c.Events <- evt:
> default:
>     // Consumer is lagging; drop rather than block.
> }
> ```
>
> There is no counter, metric, or log line anywhere when the `default`
> branch fires. A single `lodash` install generates roughly 13,000 syscall
> events against a 4096-entry-deep channel buffer, so it's entirely
> plausible for real bursts to drop events with zero indication to the
> operator or to the ML pipeline that a session's feature counts are
> undercounted.

Verified by reading, not assumed:

- Grepped all five `Run(ctx)` methods and confirmed each has exactly the
  `select { case c.Events <- evt: default: /* comment only */ }` shape the
  audit quotes, with nothing else in the `default` branch.
- Confirmed each collector's `Events` channel capacity matches the audit's
  premise: `process_collector.go` uses 1024, the other four use 4096.
- Confirmed no existing field, method, metric, or log call anywhere in
  `internal/collector/` references drops, backpressure, or channel fullness
  — the gap is real, not just undocumented.
- Checked `docs/bugs-fixed/` for any existing doc that might already cover
  this: `fix-route-drop-counting/` (H4) explicitly scopes itself to
  `RouteToSession`'s *ordering-race* drop in `internal/session/detector.go`,
  a different mechanism and a different file, and its own
  `07-findings-not-fixed.md` names H5 as open, unrelated, and unchanged.
  `fix-pending-opens-leak/` (H2) covers a *BPF map* insert failure, not a Go
  channel. No existing doc covers this collector-level channel drop.

## Goals

1. **Each of the five collectors' drops is counted** — a `DroppedEvents()`
   accessor per collector, closing "no counter."
2. **`cmd/monitor` reports nonzero drop counts at shutdown**, matching the
   existing `pending_opens`/`LOST N of M session(s)`/
   `DroppedRoutesForUnknownPID` reporting shape, closing "no metric" for the
   operator.
3. **Each counter is proven against a real drop**, not a synthetic call —
   a genuine BPF event (fork, openat, syscall, TCP connect, TCP write) must
   actually be dropped and counted, mirroring how H2's and H4's tests drove
   their counters through the real collection/routing path rather than a
   direct method call alone.
4. **Nothing else changes** — no channel resizing, no blocking-send
   fallback, no change to any collector's decode logic, BPF program, or
   `Run` loop structure beyond the one line that increments the counter.

The audit's own text doesn't ask for a log line "by default" the way H4's
did ("no log line anywhere" here just restates "no counter, metric, or log
line" as one gap) — the shutdown report in cmd/monitor (goal 2) is the
project's established stand-in for that, same as H2's and H4's shutdown
reports, so no separate verbose-mode `logf` call is added per drop; adding
one per event on a channel that can legitimately fill 13,000 times per
install would itself be a new performance/log-volume concern the audit
doesn't raise.

## How we would know

- Goal 1 → one new test per collector, each asserting `DroppedEvents()`
  moves after a forced-full channel plus one real event.
- Goal 2 → read of `cmd/monitor/main.go`'s new shutdown block; not itself
  unit-tested, consistent with how H2's and H4's equivalent shutdown lines
  were verified (see [07-findings-not-fixed.md](07-findings-not-fixed.md)).
- Goal 3 → each test drives a real BPF-sourced event (not
  `pc.dropCount++` or similar), and the full test suite — not just each new
  test run in isolation — must pass, per the TDD skill's definition of done
  and this task's explicit "to the teeth" instruction.
- Goal 4 → `git diff` limited to the five collectors' `dropCount`/
  `DroppedEvents` additions and `cmd/monitor`'s report block; full `-race`
  and root suites green.
