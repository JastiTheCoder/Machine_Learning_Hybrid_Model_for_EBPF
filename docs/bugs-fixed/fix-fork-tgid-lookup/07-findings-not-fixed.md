# 7. Findings not fixed

Two things surfaced while doing this work and were deliberately left alone, plus
one honest limit on what the reproduction actually demonstrates.

---

## A. The insert side can still write a thread id into a tgid-keyed map — Low

The fix corrects the *lookup*: `parent_pid` is now resolved via
`bpf_get_current_pid_tgid()`. It does not touch the *insert*:

```c
bpf_ringbuf_submit(evt, 0);
bpf_map_update_elem(&tracked_pids, &save_child_pid, &save_parent_pid, BPF_ANY);
```

`sched_process_fork` fires for every `copy_process()` call, which includes
`clone(CLONE_THREAD, ...)` — the syscall behind `pthread_create()` — not only
genuine new-process `fork()`. For a real `fork()`, `child_pid` is correctly the
new process's own tgid (a fork's child is always a fresh thread-group leader),
so the insert is correct in exactly the case this task's fix and test exercise.
For a `CLONE_THREAD` event — a tracked process spawning an additional thread of
*itself* — `child_pid` is that new thread's tid, not a new tgid, and it still
gets inserted into `tracked_pids` as if it were one.

**Why this is lower-impact than it sounds:** a thread of an already-tracked
process does not need its own entry to be traced correctly — every downstream
consumer (`syscall_tracer.bpf.c`, `file_monitor.bpf.c`, `tcp_monitor.bpf.c`)
resolves `bpf_get_current_pid_tgid()>>32` before checking `is_tracked()`, and
that tgid is the *process's* tgid, already present in the map from the process
being tracked in the first place. The stray entry is inert until, potentially,
Linux's pid allocator reuses that same number as a genuine tgid for some
unrelated future process — at which point that unrelated process would be
incorrectly treated as tracked. That requires a specific pid-reuse collision
and is not demonstrated here.

**Why not fixed here:** distinguishing "this fork event is a new process" from
"this fork event is a new thread of an existing process" is not possible from
the fields `trace_event_raw_sched_process_fork` actually exposes
(`parent_comm`, `parent_pid`, `child_comm`, `child_pid` — no clone-flags field,
no task_struct pointer). The reliable way to tell them apart is reading the new
child's own `tgid` via `BPF_CORE_READ` off a `task_struct*`, which this
tracepoint does not hand you directly — obtaining one would mean switching
instrumentation strategy (a fentry/fexit probe on `copy_process()` or
`wake_up_new_task()`, say), which is a materially larger change than this task's
scope, and reopens the CO-RE-relocation risk this project has already been
burned by once.

**Suggested shape:** an fexit probe on `wake_up_new_task()`, reading the new
task's own `tgid` via CO-RE, inserting into `tracked_pids` only when
`child->tgid == child->pid` (i.e., the child is its own thread-group leader — a
genuine new process).

---

## B. The reproduction is a minimal C fixture, not an observed Node.js worker-thread install

`AUDIT.md` recorded this finding as "not demonstrated in production." This task
demonstrates the underlying kernel-level mechanism deterministically — a real
`fork()` from a genuinely non-leader pthread, against the real BPF program, on
the real kernel — but it does not demonstrate a real `npm install` running a
real install script that uses Node's `worker_threads` module to fork a child
process, which was the motivating real-world scenario named in
[01-goals.md](01-goals.md).

**Why not fixed here:** constructing such a fixture package would mean writing
and installing an npm package whose install script spawns a `worker_threads.Worker`
that itself calls `child_process.spawn` or a native `fork()`, and confirming
the exact code path Node takes lands the actual `fork(2)`/`clone(2)` syscall on
a non-main OS thread (Node's own internals, not just the JS-level API, decide
that placement, and would need to be checked). That is a substantially larger
and less certain effort than the C fixture, which pins down the exact kernel
mechanism directly and is what the BPF program actually reacts to — the C
fixture and a Node worker-thread script would exercise the identical kernel
tracepoint and the identical BPF code path, so the C fixture's result should
generalise, but this is stated as reasoning, not measurement.

**Suggested next step, if this needs to be closed out fully:** a fixture
package under `context/malicious-packages/` (following this project's existing
convention for the `reverse-shell-test` / `crypto-miner-test` style fixtures)
whose `postinstall` spawns a worker thread that forks a child, run through the
real monitor exactly as in [04-how-it-was-done.md](04-how-it-was-done.md) step
12.

---

## Still open from earlier work

Carried forward unchanged:

- **`bpf/vmlinux.h` is stale** relative to the running kernel. The
  [ProcessTracer fix](../fix-processtracer-fork-load/) worked around one
  consequence; the underlying staleness can poison other CO-RE relocations.
  Regenerating needs `bpftool`.
- **`llvm-strip` is not installed**, so `go generate ./internal/collector/...`
  fails without the `BPF2GO_STRIP=/usr/bin/strip` workaround.
- **Sanitised filenames can collide** — see
  [`../fix-output-filename-sanitization/07-findings-not-fixed.md`](../fix-output-filename-sanitization/07-findings-not-fixed.md).
  Harmless while filenames carry a per-session id.
