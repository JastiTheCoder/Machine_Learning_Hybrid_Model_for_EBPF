# Fix — H2: `pending_opens` leaks and its insert failures go uncounted

This directory documents one piece of work: repairing **H2**, the first of
the audit's remaining High findings in [`../../AUDIT.md`](../../AUDIT.md),
using the test-driven workflow in `skills/.agents/skills/tdd/`.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | The two slices, including an audit-correcting detour. |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why this way and not the alternatives? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-findings-not-fixed.md](07-findings-not-fixed.md) | What was left open. |
| — | [evidence/](evidence/) | Raw, unedited output behind every claim made above. |

## One-paragraph summary

`pending_opens` (a bounded, 4096-entry BPF hash map used to pair an
`openat()`'s enter and exit probes) had two bugs bundled into one audit
finding: `bpf_map_update_elem`'s return value was never checked at the
insert site, so a full map silently dropped new file events with no signal
to userspace; and the map's only cleanup path was the syscall's own exit
probe, which the audit claimed never fires for a process killed mid-syscall.
The first half is fixed and demonstrated directly: a new `file_monitor_stats`
counter now increments whenever an insert fails, verified by filling the map
to capacity and forcing a real tracked `openat()` to fail its own insert.

## An audit-correcting finding, investigated rather than accepted

The second half produced a genuine surprise. A test built to reproduce "a
tracked process is SIGKILLed while blocked inside `openat()`" — using a real
subprocess blocked in a real `open()` on a FIFO with no writer, not a
simulation — passed against the *unmodified*, pre-fix code. Rather than
accept that as "no bug here," it was investigated: a throwaway diagnostic
showed `sys_exit_openat`'s own probe still fires for this exact scenario on
this kernel, with the interrupted return code, and cleans up the entry
itself. H2's literal premise does not hold for a `SIGKILL` delivered during
an interruptible sleep.

Three follow-up isolation builds (each toggling one of three cleanup call
sites while keeping the BPF map/program declarations — and therefore the Go
bindings — identical) established the full picture: disabling *both*
cleanup paths at once does reproduce a genuine leak, and each path alone is
independently sufficient to prevent it. A new `sched_process_exit` tracepoint
was added as a backstop regardless, for the one case that doesn't self-heal —
a thread stuck in an uninterruptible (D-state) wait, which this test
environment cannot reproduce portably. [02-tests.md](02-tests.md) and
[05-why-this-approach.md](05-why-this-approach.md) carry the full reasoning
and the isolation matrix.

## What shipped

- `file_monitor_stats`, a one-entry BPF array map, plus a checked return
  value at `pending_opens`'s insert site — read via a new
  `FileCollector.PendingOpensInsertFailures()` and reported by `cmd/monitor`
  at shutdown, matching the shape of the existing `LOST N of M session(s)`
  line.
- A new `sched/sched_process_exit` tracepoint in `file_monitor.bpf.c` that
  removes a tracked thread's own `pending_opens` entry on exit,
  unconditionally and without filtering to the thread-group leader (unlike
  `process_tracer.bpf.c`'s own handler of the same tracepoint name, which
  correctly does filter — the two maps have different keying and the
  comment on the new tracepoint explains why the same pattern would be
  wrong here).
- A stale `runDryRun` status string, discovered while confirming the fix
  loads in the real binary, corrected to name all three attached
  tracepoints.
