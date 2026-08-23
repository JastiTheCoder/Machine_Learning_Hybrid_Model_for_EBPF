# Fix — C3: a session can be completed twice

This directory documents one piece of work: repairing **C3**, the last of the
four Critical findings in [`../../AUDIT.md`](../../AUDIT.md), using the
test-driven workflow in `skills/.agents/skills/tdd/`.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | The four slices, in order, including two guards checked for teeth. |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why this way and not the alternatives? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-findings-not-fixed.md](07-findings-not-fixed.md) | What was left open. |
| — | [evidence/](evidence/) | Raw, unedited output behind every claim made above. |

## One-paragraph summary

A session could be completed from two independent goroutines racing each
other: the normal-exit path (the router goroutine, when the last live PID
exits) and the timeout callback (a `*time.Timer`'s own goroutine). Neither
checked whether the other had already done it — both only ever took the *read*
side of `completedMu`, which stops a send after shutdown but does nothing to
stop two sends before it. Measured directly: a test racing 300 independent
sessions' exit events against a 1-microsecond timeout reported **8 duplicate
deliveries out of 300** on a single run. Each duplicate meant `BuildRecord` and
`Write` ran twice for one install, the second write silently overwriting the
first at the same path (session IDs are `npm-<unix-second>`), and — bundled
into the same root cause — a session that timed out never cleaned up its own
`d.timers` entry, leaking one map entry per timeout for the life of the
process, and a `TimedOut` field written with no lock at all.

The fix adds `Session.MarkCompleteOnce(timedOut bool) bool`, a `sync.Once`-backed
arbitration primitive: exactly one caller "wins" and proceeds to unregister and
send the session; every other caller is a no-op. Both completion paths now call
it, and the timeout callback now clears its own `d.timers` entry unconditionally
before racing for the win. After the fix: 300/300 trials, zero duplicates, ten
consecutive stress runs, zero flakes.

## Two guards checked for teeth, one with them and one without

Two of the four tests written for this task pass on the first run without ever
going red. Both were checked rather than trusted, by reverting the relevant
part of the fix and re-running:

- **`TestSessionTimeoutClearsItsOwnTimerEntry`** — genuinely has teeth. Removing
  just the leak-cleanup line reproduces the leak and fails it.
- **`TestDetectorTimedOutStaysFalseWhenExitCompletesBeforeTheTimer`** — does
  **not** have teeth against C3. It still passes against the fully reverted,
  pre-fix `detector.go`, because its 200ms window and near-instant exit never
  create an actual race. Kept as an honest regression guard for the ordinary
  case, documented as such in its own comment and in
  [02-tests.md](02-tests.md).
