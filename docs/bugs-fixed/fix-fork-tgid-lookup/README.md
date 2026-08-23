# Fix — fork handler looks up a thread id against a tgid-keyed map

This directory documents one piece of work: repairing the Medium finding
recorded in [`../../AUDIT.md`](../../AUDIT.md), using the same test-driven
workflow as the three fixes before it.

Read the documents in order — they follow the sequence the work happened in.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | How was it done, step by step? |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why this way and not the alternatives? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-findings-not-fixed.md](07-findings-not-fixed.md) | What was left undone, and one thing this environment could not verify. |
| — | [evidence/](evidence/) | Raw, unedited output behind every claim made above. |

## One-paragraph summary

`tracked_pids` is a hash map keyed by thread-group id (tgid) everywhere it is
used: the exec handler inserts `bpf_get_current_pid_tgid()>>32`, the exit
handler only fires when `tid == tgid` and says so in its own comment
("tracked_pids stores tgids, not individual thread ids"), and every other BPF
program that reads it — `syscall_tracer.bpf.c`, `file_monitor.bpf.c`,
`tcp_monitor.bpf.c` — looks it up by that same tgid. The `sched_process_fork`
handler was the one outlier: it looked a process up by
`ctx->parent_pid`, which the kernel's tracepoint sets to the calling *task's*
own id — its thread id, not its process's tgid. For a single-threaded process
those are the same number, so the bug was invisible in the overwhelmingly
common case. For a tracked process that forks from a thread other than its
main one, the lookup missed, and the fork event — and the child's entire
subtree — was silently never reported. That is exactly the shape of evasion a
malicious install script forking from a worker thread would produce, which is
what this monitor exists to catch.

The fix reads the tgid from `bpf_get_current_pid_tgid()` instead of the
tracepoint's `parent_pid` field — the same call every other consumer of this
map already makes. Proven with a small C fixture that forks deterministically
from a pthread that is not the process's leader thread, rather than relying on
however the test process's own runtime happens to schedule things.

A useful side effect: the pre-existing `TestProcessCollectorReportsForkOfTrackedProcess`
worked around this exact bug by seeding *every* thread id of the test process into
`tracked_pids`, rather than just its pid. With the fix in place that workaround is
no longer needed and has been removed; the test now seeds only the tgid and stays
green across repeated runs.
