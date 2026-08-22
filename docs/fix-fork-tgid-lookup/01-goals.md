# 1. Goals

## The defect

Recorded as the Medium finding in `AUDIT.md`:

> the fork handler filters a thread id against a tgid-keyed map. `sched_process_fork`
> reports `parent_pid` as the forking task's id, but `tracked_pids` is keyed by
> tgid. For a multithreaded process forking from a non-leader thread the lookup
> misses and the fork event — and that child's whole subtree — is silently
> dropped. Not demonstrated in production.

`bpf/process_tracer.bpf.c`, before this change:

```c
SEC("tp/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 parent_pid = (__u32)ctx->parent_pid;
    __u32 child_pid  = (__u32)ctx->child_pid;
    ...
    if (!is_tracked(parent_pid))
        return 0;
```

`ctx->parent_pid` comes from the kernel's own `TRACE_EVENT(sched_process_fork,
...)` definition, which sets `__entry->parent_pid = parent->pid` — and in the
kernel's `task_struct`, `pid` is the *thread* id, `tgid` is the process id every
thread in a thread group shares. `tracked_pids` is keyed by tgid throughout the
rest of this codebase:

- the exec handler inserts `bpf_get_current_pid_tgid()>>32` (`process_tracer.bpf.c`);
- the exit handler only fires when `tid == tgid`, with the comment "tracked_pids
  stores tgids, not individual thread ids" (`process_tracer.bpf.c`);
- `syscall_tracer.bpf.c`, `file_monitor.bpf.c`, `tcp_monitor.bpf.c` all resolve
  `tgid = bpf_get_current_pid_tgid()>>32` before calling `is_tracked(tgid)`.

The fork handler was the one place using a raw thread id instead.

## Why this matters for this specific project

`tracked_pids` is how the monitor decides "this process belongs to the npm
install being watched, follow its children." A process that forks a child from
a thread other than its main one produces a `parent_pid` the map was never
populated with, so the lookup silently misses. Node.js's `worker_threads`
module makes this directly reachable from JavaScript: an install script that
runs `child_process.spawn` (or a raw `fork()` via a native addon) from inside a
worker thread evades the tracker entirely, and everything that child does —
every file it touches, every socket it opens — goes unrecorded. Given the
capstone project's purpose — training a classifier to recognise malicious
install scripts, using fixtures literally named `reverse-shell-test`,
`crypto-miner-test`, `env-stealer-test` — a blind spot that is this easy to hit
deliberately is a real gap, not an academic one.

## Goals

1. **The fork handler must resolve the tracked process's tgid correctly**,
   regardless of which of its threads issued the `fork()`/`clone()` that
   triggered the tracepoint.
2. **Prove it against a deterministic, non-leader-thread fork** — not one that
   merely happens to land on the right OS thread, which would leave the test
   able to pass or fail depending on scheduling.
3. **Do not regress the ordinary case.** A normal `npm install`, where npm and
   its children are single-threaded processes forking from their own main
   thread, must keep working exactly as before.
4. **Load cleanly.** `bpf_get_current_pid_tgid()` is a long-stable helper (used
   throughout this codebase already), so no new CO-RE relocation risk should be
   introduced — but this must be checked, not assumed, given the project's
   history with poisoned relocations.

## How we would know

- Goal 1, 2 → a test that forks from a pthread known not to be the process
  leader, seeding `tracked_pids` with only the tgid, and asserts the resulting
  FORK event still arrives.
- Goal 3 → the existing fork test, plus a real `npm install` through the real
  monitor binary, checked for an unchanged `process_tree`.
- Goal 4 → `TestNewProcessCollectorLoadsAndAttaches`, plus the whole-repository
  suite under `-race` and under root.
