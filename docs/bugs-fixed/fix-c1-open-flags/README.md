# Fix C1 — `write_processes` / `read_processes` are structurally broken

This directory documents a single piece of work: repairing the defect recorded as
**Critical finding C1** in [`../../AUDIT.md`](../../AUDIT.md), using a test-driven
workflow.

Read the documents in order. They follow the sequence the work actually happened in:
the goals were fixed before anything was written, the tests were written before the
code, and the results were measured afterwards.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | How was it done, step by step? |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why this way and not another? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-out-of-scope-blocker.md](07-out-of-scope-blocker.md) | A separate pre-existing bug found on the way, deliberately **not** fixed. |
| — | [evidence/](evidence/) | Raw, unedited test output for every claim made above. |

## One-paragraph summary

`bpf/file_monitor.bpf.c` hardcoded `evt->flags = 0` on every file-open event it
emitted, because the `sys_exit_openat` tracepoint context does not carry the
syscall's arguments and the enter-side probe was not saving them. Since
`O_RDONLY == 0` on Linux, every open in every session ever captured was classified
as a read. The QUT-DV25 feature `write_processes` was therefore **always 0**, and
`read_processes` was inflated to "every process that touched a file". The fix
captures `ctx->args[2]` in the enter probe, carries it through the existing
`pending_opens` map, and writes it to the event in the exit probe. Measured against
a real `npm install`: 1,469 of 1,473 captured file events now carry real flags
(previously 0 of 1,473), and `write_processes` went from `0` to a correct non-zero
value.

## Scope boundary

This work fixes C1 only. While validating end-to-end, the monitor binary was found to
be unable to start at all on this kernel for an unrelated, pre-existing reason. That
is documented in [07-out-of-scope-blocker.md](07-out-of-scope-blocker.md) with a full
root-cause analysis, but it was **not** fixed here, because it is a different defect
in a different BPF program and repairing it was not part of this task.
