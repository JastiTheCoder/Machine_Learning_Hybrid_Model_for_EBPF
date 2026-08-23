# Fix — ProcessTracer fails to load on current kernels

This directory documents a single piece of work: repairing the defect recorded in
[`../fix-c1-open-flags/07-out-of-scope-blocker.md`](../fix-c1-open-flags/07-out-of-scope-blocker.md),
using the same test-driven workflow as the C1 fix.

Read the documents in order — they follow the sequence the work happened in.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | How was it done, step by step? |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why this way and not the alternatives? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-findings-not-fixed.md](07-findings-not-fixed.md) | Two further bugs found on the way, deliberately **not** fixed. |
| — | [evidence/](evidence/) | Raw, unedited output for every claim made above. |

## One-paragraph summary

`tracepoint__sched__sched_process_fork` read the child's process name from
`ctx->child_comm`. `bpf/vmlinux.h` is a stale dump declaring that field as
`char child_comm[16]`, but current kernels declare it with `__string()`, storing it as a
`__data_loc` u32 descriptor instead of an inline array. CO-RE cannot relocate a
`char[16]` access onto that layout, so cilium/ebpf poisoned the instruction with
`0xBAD2310`, the verifier rejected the program, and **the monitor binary exited on
startup and could not capture anything at all**. The fix replaces that one field read
with `bpf_get_current_comm()` — the helper the sibling exec and exit handlers in the
same file already use — which returns the same string with no relocation. One line of
kernel code changed.

The payoff is bigger than the fix: with the monitor able to start, the
[C1 open-flags fix](../fix-c1-open-flags/) could finally be confirmed the way it always
should have been — in a session JSON written by the real binary during a real
`npm install`, reporting `"write_processes": 1` where every previously captured session
reported `0`.
