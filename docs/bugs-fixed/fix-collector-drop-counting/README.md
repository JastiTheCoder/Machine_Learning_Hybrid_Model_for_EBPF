# Fix — H5: uncounted, unlogged event drops under channel backpressure

This directory documents one piece of work: repairing **H5**, the fifth of
the audit's High findings in [`../../AUDIT.md`](../../AUDIT.md), using the
test-driven workflow in `skills/.agents/skills/tdd/`.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written or extended, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | Step by step. |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why counting, not eliminating the backpressure? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-findings-not-fixed.md](07-findings-not-fixed.md) | What was left open. |
| — | [evidence/](evidence/) | Raw, unedited output behind every claim made above. |

## One-paragraph summary

All five collectors (`process_collector.go`, `syscall_collector.go`,
`file_collector.go`, `tcp_collector.go`, `bytes_collector.go`) read their own
ring buffer in their own goroutine and forward each decoded event to a
buffered `Events` channel via `select { case c.Events <- evt: default: }`.
When the consumer is slower than the producer, the `default` branch fires
and the event is gone — no counter, no metric, no log line, anywhere. The
audit calls out that a single `lodash` install generates roughly 13,000
syscall events against a 4096-entry channel, so real bursts silently
undercounting a session's features is entirely plausible in production, with
nothing to tell the operator or the ML pipeline it happened. This fix gives
each collector a `dropCount`/`DroppedEvents()` atomic counter at its exact
drop site and a shutdown report in `cmd/monitor`, the same "count it, report
it, never fail silently" shape used for H2's `pending_opens` counter and
H4's `DroppedRoutesForUnknownPID`.

Verifying this fix, by running the *full* test suite rather than each new
test in isolation, surfaced a second, unrelated real bug: `ProcessCollector`
is the one collector whose kernel-side emission is not gated by
`is_tracked()` — its `sys_enter_execve` handler fires for every execve() on
the machine, tracked or not. Under the concurrent process-spawning load of a
full `go test ./...` run, that made a naive test for this exact fix
deadlock permanently. That test bug (not a production bug) is fixed here as
well, since it blocked verifying H5 at all; see
[04-how-it-was-done.md](04-how-it-was-done.md) and
[07-findings-not-fixed.md](07-findings-not-fixed.md) for the full account
and why the underlying asymmetry itself is a fresh finding, not something
this task's scope covers.

## What shipped

- `DroppedEvents() uint64` on all five collectors — an atomic counter,
  incremented every time that collector's `Run` goroutine hits the
  `default:` branch of its `Events` send.
- `cmd/monitor` reports each collector's nonzero drop count at shutdown,
  matching the shape of the existing `pending_opens`/`LOST N of M
  session(s)`/`DroppedRoutesForUnknownPID` reports.
- One new test per collector, each triggering a genuine drop via a real BPF
  event (a real fork, a real `openat()`, a real syscall, a real loopback TCP
  connect, a real loopback TCP write) rather than a synthetic call —
  `TestProcessCollectorCountsDroppedEvents`,
  `TestFileCollectorCountsDroppedEvents`,
  `TestSyscallCollectorCountsDroppedEvents`,
  `TestTcpCollectorCountsDroppedEvents`,
  `TestBytesCollectorCountsDroppedEvents`.
- A fixed, deadlock-free version of the `ProcessCollector` test, plus a
  from-scratch reproduction proving the original (blocking-fill,
  absolute-zero-baseline) version of that test genuinely hangs under
  concurrent exec load — not just "didn't happen to fail this run."
