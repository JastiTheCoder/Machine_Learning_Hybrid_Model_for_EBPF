# Fix — C2: `BuildRecord` reads session state with no locking

This directory documents one piece of work: repairing **C2**, one of the four
Critical findings in [`../../AUDIT.md`](../../AUDIT.md), using the test-driven
workflow in `skills/.agents/skills/tdd/`.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | The four slices, in order, including one that failed. |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why this way and not the alternatives? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-findings-not-fixed.md](07-findings-not-fixed.md) | What was left open, including a seam that could not be tested. |
| — | [evidence/](evidence/) | Raw, unedited output behind every claim made above. |

## One-paragraph summary

`BuildRecord` read `sess.SyscallCounts`, `sess.ProcessTree`, `sess.TimedOut` and
four aggregators straight off the `*Session`, without ever taking `sess.mu` —
while every mutator (`AddSyscall`, `AddFile`, `AddTCP`, `AddProcess`,
`AddBytes`) takes it. Of the four aggregators, only `FiletopAggregator` carries
a mutex of its own; `DirCounts`, `TCPAggregator` and `NGramCounter` have none
and rely entirely on `session.mu`.

Because `Session.SyscallCounts` and `TCPAggregator`'s four sets are Go maps,
this is not merely inconsistent output — an unsynchronised map read against a
concurrent write is `fatal error: concurrent map read and map write`, an
**unrecoverable process crash that loses every in-flight session** in the
capture run.

Measured: a test driving collector writes against `BuildRecord` reported
**10 distinct data races** before the fix and **0** after.

The fix adds `Session.Snapshot()`, which takes `s.mu` once and returns a plain
value struct with cloned maps. `BuildRecord` now consumes that instead of
reaching into the session.

## An honest negative result

One of the four agreed seams — "end-to-end via Detector" — turned out **not to
be able to reproduce this race at all**. That was verified rather than assumed,
by reverting the fix and re-running the test: it still passed with zero races.
It is documented as such in [02-tests.md](02-tests.md) and kept only for the
integration coverage it genuinely does provide.
