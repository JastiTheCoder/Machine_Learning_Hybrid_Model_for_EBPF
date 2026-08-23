# 5. Why it was done this way

Each decision below had a plausible alternative. This records what was chosen and what
was given up.

## Why fix the producer, not the consumer

**Alternative considered:** infer write intent in userspace — e.g. treat any open under
`node_modules/` as a write, or correlate opens with subsequent `write(2)` syscalls
already captured by `syscall_tracer`.

**Rejected because** it substitutes a heuristic for a fact. The kernel *knows* the
flags; they were being discarded three lines before the ring buffer submit. Any
userspace inference would be a model of the truth, and would need its own validation,
tuning and documentation — while the actual value sat one field away. It would also
have left `evt->flags` permanently dead in the wire format, a trap for the next
reader.

The generalisation: when a value is being thrown away at the source, fetch it from the
source. Reconstructing it downstream is strictly more code and strictly less accurate.

## Why the flags are carried through `pending_opens` rather than read at exit

Not a preference — a constraint. `struct trace_event_raw_sys_exit` contains only
`unsigned long long id` and `long ret`. The syscall arguments do not exist in that
context. Anything that needs an argument at exit time must have saved it at enter
time.

`pending_opens` was already doing exactly this for `dir_category`, with the enter-side
insert, the exit-side lookup, and the `bpf_map_delete_elem` cleanup all in place. Adding
a `__u32` to that struct reuses a proven path and adds no new failure mode. The
alternative — a second map keyed the same way — would double the bookkeeping and double
the existing leak surface (audit finding H1) for no benefit.

A comment was left at the assignment site explaining *why* the value comes from the
enter probe, because "why isn't this read from `ctx` like everything else?" is the
obvious question a future reader will have, and the answer is not visible locally.

## Why `O_RDWR` counts as both

**Alternative considered:** count `O_RDWR` as a write only, on the grounds that writing
is the security-relevant signal for malware detection and that double-counting inflates
`read_processes`.

**Chosen: count as both.** Reasons:

1. **The field names are descriptive, not inferential.** `read_processes` means
   "processes that read files". A process that opens a file `O_RDWR` has requested read
   access. Reporting it as a non-reader would make the feature's name a lie.
2. **The QUT-DV25 schema is a general behavioural fingerprint**, not a
   purpose-built malware flag. Distorting one feature to sharpen a hoped-for signal is
   the kind of thing that produces a classifier that works on one dataset and nowhere
   else.
3. **The classifier can learn the relationship.** `read_processes` and
   `write_processes` are both inputs; a Random Forest is perfectly capable of using
   their ratio or difference. Pre-baking an opinion into feature extraction removes
   information rather than adding it.
4. **Reversibility.** If the counting rule turns out to be wrong, it is one boolean
   condition in one function with a test pinning it. If the *flags* were wrong, every
   captured session would be worthless. Getting the mechanism right and the policy
   adjustable is the right order.

This was raised as an explicit decision rather than being made silently, because it
changes the meaning of a published feature.

## Why the test suite needs root, and why that was not worked around

**Alternative considered:** a mock or fake `FileCollector` emitting synthetic events, so
tests run unprivileged in CI.

**Rejected**, and this is the most important decision in the change. A fake collector is
exactly the test that already existed and already passed for the entire life of the bug.
`TestFiletopAggregatorParsesWriteFlags` hand-builds `FileEvent{Flags: O_WRONLY}` and
asserts the aggregator handles it — which it always did. The defect was that nothing
*upstream* ever produced such an event. A mock cannot detect a bug in the thing it is
mocking.

The TDD skill's guidance is to mock at system boundaries and not to mock things you
own. The BPF program is not a boundary to be stubbed here — it is the code under test.

So the seam was placed at the real kernel, root access was arranged, and the tests
`t.Skip` when not privileged. The cost is honest and stated: **these tests do not run
unprivileged, so an unprivileged `go test ./...` will report all-green while C1-class
bugs are present.** That is a real gap in CI, and it should be closed by running the
suite as root somewhere, not by softening the test.

## Why an end-to-end npm test on top of the syscall-level one

Slice 3 proves flags survive one `openat`. It does not prove the *feature* is fixed:
`write_processes` is what the audit finding names, and it is produced by an aggregator
consuming thousands of events from a real process tree.

The in-run control (aggregating the same stream twice, once with `Flags` zeroed) exists
because a naive before/after across two npm runs would not be sound — npm's file access
varies with cache state, and a difference could be attributed to almost anything. One
stream, two aggregators, one assertion each: the only variable is the flags.

## Why the pre-fix state was reproduced rather than described

The RED evidence in [`evidence/`](evidence/) was regenerated at the end of the work by
temporarily reverting each fix — checking the pre-fix `.o` back out of git for slices 3
and 4, and reverting the one condition for slice 1.

This was done because a claim that a test "failed before the fix" is only worth
something if it can be reproduced on demand. The logs in `evidence/` are actual output
from actual failing runs on the current machine, not transcriptions.

## On the `strip` workaround

Generation currently requires `BPF2GO_STRIP=/usr/bin/strip` because `llvm-strip` is not
installed. GNU `strip -g` was verified to preserve `.BTF`/`.BTF.ext`, and the resulting
object loads, attaches and passes its tests — but GNU `strip` is not BPF-aware and this
should not be relied on.

**Recommendation:** install the LLVM binutils and drop the override. The `Makefile`
already pins `clang-14`/`llvm-strip-14` in a variable that is never actually wired into
the generate step (a pre-existing audit finding); wiring it up would fix both problems
at once. This was left alone as out of scope.

## Why the ProcessTracer blocker was not fixed

It is a genuine, verified, Critical-severity bug that stops the monitor from starting
at all on this kernel — and it is a *different* bug, in a different BPF program, with a
different root cause, discovered incidentally.

Folding it into this change would have meant editing `process_tracer.bpf.c`,
regenerating a second object, and quite possibly regenerating the stale `vmlinux.h`
that is the underlying cause — a change of comparable size to this one, on a component
nobody asked to have touched.

It is fully root-caused in [07-out-of-scope-blocker.md](07-out-of-scope-blocker.md) so
it can be picked up deliberately. Deciding whether to spend that effort is the
maintainer's call, not something to be quietly bundled into an unrelated fix.
