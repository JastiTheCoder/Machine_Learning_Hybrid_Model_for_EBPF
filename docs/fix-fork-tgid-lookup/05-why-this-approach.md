# 5. Why this approach

## Why `bpf_get_current_pid_tgid()` instead of, say, walking to the thread-group leader

Two ways to get the right number were available. One: read
`bpf_get_current_pid_tgid()>>32`, which the kernel computes for you. Two: use
`BPF_CORE_READ` to walk `task->group_leader->pid` or similar from
`bpf_get_current_task()`.

The first was chosen because it is what every other consumer of this exact map
already does — `syscall_tracer.bpf.c`, `file_monitor.bpf.c`,
`tcp_monitor.bpf.c` all resolve the tgid this same way before calling
`is_tracked()`. Matching the established convention means a future reader who
has seen any of those three files already recognises the pattern here, and it
is one helper call rather than a CO-RE field traversal. The second approach
would also have reopened exactly the risk the [ProcessTracer load-failure
fix](../fix-processtracer-fork-load/) closed: that fix specifically replaced a
struct-field CO-RE read with `bpf_get_current_comm()` because CO-RE relocations
onto struct layouts are what a stale `bpf/vmlinux.h` breaks. There was no reason
to walk back toward that risk when a stable helper already does the job.

## Why `current`'s pid_tgid is even the right value here

This tracepoint fires inside `copy_process()`, before the new child task is
fully installed — the executing context (`current`) is the *parent*, the
forking task, for the entire duration of the handler. So
`bpf_get_current_pid_tgid()` genuinely reads the forking task's own identity,
not some other thread's. This was verified by the fixture itself: the tgid the
test seeds is read from the fixture's own `PARENT_PID` line, printed before any
forking happens, and the resulting event's `Ppid` was asserted to equal exactly
that value — not just "some tid that happened to match."

## Why a C fixture rather than staying inside Go

Go does not expose a way to force a `fork(2)` (as opposed to
`clone(CLONE_VM|...)`, which is what Go's own goroutine/thread machinery uses)
from a specific, chosen, non-leader OS thread on demand. `exec.Command` gets
close but leaves the choice of thread to the runtime scheduler — usable for a
*regression* check (as in Test 3), useless for a *deterministic* red.

A ~60-line C program using `pthread_create` + `fork()` is small, has zero
dependencies beyond libc, and its correctness is checkable in isolation before
any BPF code is involved (Step 3 in [04-how-it-was-done.md](04-how-it-was-done.md)).
This is the same "test where the truth is" principle the three previous fixes
each applied in their own way: here, the truth about *which thread issued the
syscall* can only be pinned down by controlling that thread directly, and C is
the tool that lets you do that.

## Why the fixture's stdout is read for the actual PIDs rather than assumed

The test never guesses what `PARENT_PID` or `CHILD_PID` will be — it starts the
fixture, reads its own announcement of each value off a pipe, and only then
acts. This mirrors the caution the `tdd` skill asks for around expected
values ("come up with the correct answer independent of the implementation"):
the values here come from the OS via the fixture's own `getpid()` /
`fork()`-return calls, not from any assumption inside the test about what pids
"should" be.

## Why the pre-existing test was run as a control before writing any code

It would have been possible to jump straight to writing the new failing test.
Running the old one first, unmodified, and recording that it passed produces
something the new test alone cannot: direct evidence that the *existing*
coverage was insufficient, and a citation for *why* (its own comment says so).
Without that step, a reader would have to take on faith that the old test
wasn't already catching this. This is the same discipline the
[C1 fix](../fix-c1-open-flags/) applied to
`TestFiletopAggregatorParsesWriteFlags` — a defect this well-hidden deserves to
have its concealment demonstrated, not just asserted.

## Why the workaround was removed rather than left alongside the new test

Leaving `selfTaskIDs` and the every-tid seeding in place would have cost
nothing to keep — it still passes. It was removed anyway, because a workaround
whose reason for existing has been fixed is now actively misleading: a future
reader hitting that code has to go figure out whether it is still protecting
against something real. Since the fix generalises (Test 3 in
[02-tests.md](02-tests.md) proves this, run three times to rule out scheduling
luck), the honest thing to leave behind is a test that seeds the way a correct
caller actually would.

## Why the ordinary-case regression check used the real binary, not another unit test

Goal 3 is "the common path is unaffected." The existing fork tests already
cover the mechanics of that at the unit level (a single-threaded fork produces
a correct event either way — the bug is invisible there by definition). What
those tests cannot show is that the change is invisible all the way through the
*shipped binary*, across session detection, feature aggregation, and JSON
output — the same reasoning the previous three fixes each applied to their own
end-to-end steps. A real `npm install` through the real `cmd/monitor` is the
cheapest way to check that nothing further downstream reacts to the changed
fork handler.
