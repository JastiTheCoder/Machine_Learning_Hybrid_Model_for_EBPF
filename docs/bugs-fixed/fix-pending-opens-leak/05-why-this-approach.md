# 5. Why this approach

## Why a stats array map, not `bpf_printk` or a ring-buffer event

`bpf_printk` was rejected outright: it writes to the kernel's shared trace
pipe, requires the operator to separately be reading
`/sys/kernel/debug/tracing/trace_pipe`, and is a debugging aid, not a
production signal — nothing in `cmd/monitor` could react to it or report it
at shutdown.

A ring-buffer event (matching how every other piece of data leaves these BPF
programs) was considered and rejected as overkill for a single counter: it
would need a new event struct, a new Go decode path, and a consumer goroutine,
all to carry one `u64` that only needs to be read once, at shutdown. A
one-entry `BPF_MAP_TYPE_ARRAY` read via a single `Lookup` call is the
smallest correct interface for "how many times did this fail since the
program loaded" — no polling loop, no channel, no risk of the counter itself
being dropped under backpressure the way a ring-buffer event could be.

## Why `sched_process_exit`, and why it does not filter to the thread-group leader

The natural instinct, copying `process_tracer.bpf.c`'s own handler, is to
gate cleanup on `tid == tgid` (leader-only). That would be wrong here:
`tracked_pids` is keyed by tgid, so only the leader's exit needs to trigger
its removal — but `pending_opens` is keyed by the *full* `pid_tgid` of
whichever thread called `openat()`. A non-leader thread that dies mid-syscall
would leave its own entry behind forever if cleanup were leader-gated, which
is exactly the bug being fixed. The doc comment on the new tracepoint states
this asymmetry explicitly, because "copy the sibling file's pattern" is
otherwise the natural (and wrong) thing to do here.

`is_tracked(tgid)` is still checked before the delete, matching the cost
profile of every other tracepoint in this file (`sys_enter_openat` also
gates on `is_tracked` first) rather than running an unconditional map
operation for every process exit on the system.

## Why the leak test was kept and reframed rather than deleted, once it stopped being a red

The tempting move once the diagnostic explained the surprise pass would have
been to declare "no leak reachable, nothing to test" and drop the scenario.
That would have thrown away the one piece of evidence that the underlying
concern in H2 is real: the all-cleanup-disabled isolation run, which does
leak. The test earns its place for a different reason than originally
intended — it now proves the map *can* leak in principle, and that the fix
(either path) closes it, rather than proving the audit's specific SIGKILL
scenario was ever actually vulnerable on this kernel. Both the test's doc
comment and this doc say so plainly, matching the standard set by
[`../fix-c2-buildrecord-race/05-why-this-approach.md`](../fix-c2-buildrecord-race/05-why-this-approach.md)'s
"why the failed seam was kept and relabelled rather than deleted."

## Why the new hook is kept despite not being provably necessary for the reproducible scenario

Isolation proved the pre-existing `sys_exit_openat` path alone already
handles a `SIGKILL` delivered during an interruptible sleep. The remaining
case — a thread that dies without ever returning from `openat()` because it
is stuck in an *uninterruptible* wait (D-state) on an unresponsive
filesystem — cannot be dismissed as theoretical: it is exactly the kind of
condition a long, unattended capture run of many `npm install`s eventually
hits (a hung network mount, a misbehaving FUSE overlay, or — worth naming
plainly, since this project's whole purpose is watching for hostile install
scripts — a malicious package deliberately trying to wedge a syscall against
the monitor's own bounded map as a denial-of-service). The hook costs one
`is_tracked` lookup per process exit on the system when it does nothing, and
one map delete when it does; that is a price worth paying for a backstop
against a scenario this environment cannot reproduce portably, rather than
leaving `pending_opens` with only a single cleanup path for the case the
audit was actually worried about (an unbounded resource during a long run).

## Why the isolation matrix, not just "it passes"

A single pass-after-implementing tells you the code didn't regress; it does
not tell you *why* it passes, and for a map with two independent writers-of-
zero (two delete sites plus a new one), "why" matters for anyone maintaining
this file later. Three cheap rebuild-and-rerun cycles turned "it works" into
"here is exactly which of three deletion points is load-bearing for which
scenario" — the same value a teeth check always provides, applied three times
instead of once because there were three configurations worth distinguishing,
not two.
