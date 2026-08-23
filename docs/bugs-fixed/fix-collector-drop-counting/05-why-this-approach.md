# 5. Why this approach

## Why counting, not eliminating the backpressure

A larger channel buffer, a blocking send with a bounded timeout, or a
secondary overflow buffer would all reduce *how often* the drop happens,
but none of them eliminate it — a sufficiently large burst (the audit's own
~13,000-syscall `lodash` example against a 4096-entry buffer) can still
outrun any finite buffer, and a blocking send just moves the cost from "lost
event" to "the ring-buffer reader stalls, and the kernel itself starts
dropping ring-buffer samples instead" — a strictly worse failure mode,
since ring-buffer drops aren't even visible to the reader loop's own error
handling the way a full Go channel is. This mirrors H4's own reasoning
exactly (see `../fix-route-drop-counting/05-why-this-approach.md`): the
audit frames the underlying condition as a real, physical resource limit,
not a bug in the `select` structure itself, and this project's fix series
has consistently chosen "make it visible" over "add a new buffering
subsystem" for exactly that class of finding (H2's `pending_opens` insert
failures, H4's `RouteToSession` drops). A resizing/backoff redesign is also
disproportionate to what H5 actually asks for — its own wording is "there
is no counter, metric, or log line," not "the channel is too small."

## Why `sync/atomic` rather than a mutex

Each collector's `Run` goroutine is the sole writer to `dropCount`, and
`DroppedEvents()` (typically called once, from `cmd/monitor` at shutdown,
possibly concurrently with `Run` still draining a final few events during
shutdown) is the sole reader from any other goroutine. A mutex would work
but adds unneeded overhead on a value written once per dropped event; a
single atomic counter is the same tool this project has used for every
other drop/failure counter in this fix series (H2's `pending_opens` insert
failures, H4's `DroppedRoutesForUnknownPID`), for consistency and because
the access pattern is identical: one writer goroutine, occasional readers.

## Why five separate `dropCount` fields, not one shared counter

The audit's finding is phrased per-collector ("all five collectors... use
the same pattern"), and `cmd/monitor`'s existing shutdown reports
(`pending_opens`, `DroppedRoutesForUnknownPID`) are already broken out by
what they measure rather than merged into one aggregate number — an
operator debugging undercounted features needs to know *which* event
stream lost data (a burst of dropped TCP events points at network-heavy
installs; dropped syscall events point at something else entirely), which
a single combined counter would destroy.

## Why `ProcessCollector`'s test needed a different shape from the other four

`file_monitor.bpf.c`, `syscall_tracer.bpf.c`, and `tcp_monitor.bpf.c` all
gate event emission on `is_tracked(pid)` before ever touching their ring
buffer, so their four tests' plain blocking fill loop and absolute
`DroppedEvents() == 0` baseline are both sound: nothing untracked can put
anything into those channels, so nothing can outrace or invalidate the
test's own setup. `process_tracer.bpf.c`'s `sys_enter_execve` handler
cannot be gated the same way — tracking a PID begins at its own exec event,
so the first event for any newly-tracked process must, by construction,
reach userspace before `is_tracked()` could ever say yes for it. That
asymmetry is architectural, not a bug in this fix's scope (see
[07-findings-not-fixed.md](07-findings-not-fixed.md)), but it does mean
`ProcessCollector.Events` is the one channel in the whole codebase that
real, unrelated, system-wide activity can fill *before this test's own
setup runs at all*. Fixing only the test (non-blocking fill, relative
assertion) rather than trying to make the BPF program gate at exec time was
the right scope boundary: gating `sys_enter_execve` on `is_tracked()` would
either miss every process's own first exec permanently (defeating the
collector's purpose) or need new logic to special-case "the exec that
starts tracking" — a production behavior change this task was not asked to
make and that H5 doesn't call for.

## Why the deadlock was reproduced under controlled load rather than just re-run once

"The fixed test passed once" is not the same claim as "the race is closed."
The original full-suite run that surfaced the hang depended on incidental,
uncontrolled concurrency from unrelated packages' subprocess-spawning tests
— not a reliable, repeatable trigger. Reconstructing the broken version in
isolation and driving it against a controlled, large, artificial exec load
(3,000 concurrent `/bin/true` spawns) makes the reproduction deterministic
and independent of whatever else happens to be running in the suite at the
time, which is what this task's explicit "to the teeth" instruction and the
CLAUDE.md race-condition test-notes requirement both call for: a test that
merely exercises the code path once is not sufficient proof for a
timing-dependent bug.
