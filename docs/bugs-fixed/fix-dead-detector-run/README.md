# Fix — H3: dead `Detector.Run()`/`Submit*` machinery

This directory documents one piece of work: repairing **H3**, the third of
the audit's High findings in [`../../AUDIT.md`](../../AUDIT.md), using the
test-driven workflow in `skills/.agents/skills/tdd/`.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written or migrated, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | Step by step, including the subtlety that reshaped the fix. |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why this way and not the alternatives? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-findings-not-fixed.md](07-findings-not-fixed.md) | What was left open. |
| — | [evidence/](evidence/) | Raw, unedited output behind every claim made above. |

## One-paragraph summary

`Detector.Run()` and its four `SubmitProcess/Syscall/File/TCP` methods
queued collector events onto `Detector`'s own private channels for `Run()`'s
loop to drain and dispatch. Production never called `Submit*` — a repo-wide
grep confirmed zero non-test callers — because `cmd/monitor/main.go` has
always wired a `Router` directly to the real collector channels, calling
`HandleProcess`/`RouteToSession` itself. The consequence: eight tests across
two packages (five named directly in the audit, three more found while
investigating — including three from this project's own C3 fix) drove the
detector entirely through a path the real binary never executes, while
`router_test.go` was the only file exercising production's actual wiring.

## A subtlety that reshaped the fix

Reading `Run()`'s body before deleting it surfaced something the audit's
wording doesn't call out: `Run()`'s `defer d.closeCompletedSessions()` was
load-bearing. `cmd/monitor`'s output worker does `for completed := range
detector.Completed()`, which only terminates when that channel *closes* —
and `Run()`, despite its internal event machinery being fully dead, was the
only thing that ever called `closeCompletedSessions()`. Deleting `Run()`
outright would have broken graceful shutdown, not fixed a coverage gap.

The fix keeps that one real behavior, split into its own honestly-scoped
method:

```go
func (d *Detector) Shutdown(ctx context.Context) {
	<-ctx.Done()
	d.closeCompletedSessions()
}
```

## What shipped

- `Detector.Run()` and all four `Submit*` methods, plus their four backing
  channel fields, removed entirely.
- `Detector.Shutdown(ctx)` added — the one real job `Run()` did, named for
  what it actually does.
- `cmd/monitor/main.go`'s one call site updated: `detector.Run(ctx)` →
  `detector.Shutdown(ctx)`.
- All eight affected tests migrated onto a real `session.Router` — the exact
  production wiring, not an approximation of it — with every original
  assertion unchanged. One test renamed
  (`TestDetector_ContextCancellationClosesCompleted` →
  `TestDetector_ShutdownClosesCompleted`) to match the method it now tests.
