# 1. Goals

Agreed **before** any test or code was written.

## Background: what was broken

The `monitor` binary could not start. `main.go` calls `NewProcessCollector()` during
startup and exits if it returns an error; it returned:

```
load ProcessTracer objects: field TracepointSchedSchedProcessFork:
  program tracepoint__sched__sched_process_fork:
  load program: invalid argument: invalid func unknown#195896080
```

`195896080` is `0x0BAD2310`, cilium/ebpf's poison value for a **failed CO-RE
relocation** (`btf/core.go:44`). When a field access cannot be resolved against the
running kernel's BTF, the library rewrites the instruction as a call to a nonexistent
helper; the verifier then rejects the program if that instruction is reachable.

The unresolvable access was `ctx->child_comm` in the fork handler. `bpf/vmlinux.h`
declares:

```c
struct trace_event_raw_sched_process_fork {
	struct trace_entry ent;
	char parent_comm[16];
	pid_t parent_pid;
	char child_comm[16];
	pid_t child_pid;
	char __data[0];
};
```

The running kernel actually has:

```
offset=0    ent                     struct trace_entry
offset=8    __data_loc_parent_comm  u32
offset=12   parent_pid              pid_t
offset=16   __data_loc_child_comm   u32
offset=20   child_pid               pid_t
```

Upstream converted this tracepoint's `__array(char, comm, TASK_COMM_LEN)` fields to
`__string(...)`, which stores them as dynamic `__data_loc` descriptors in the trailing
`__data` region. `parent_pid` and `child_pid` still relocate correctly — CO-RE finds
them by name and rewrites their offsets from 24/44 to 12/20, which the verifier log
confirms. But `child_comm` no longer exists as a `char[16]`, so that one access is
poisoned.

This is the failure mode CO-RE exists to absorb, and it does absorb it — for changed
field *offsets*. It cannot absorb a field that changed *kind*.

## Goal 1 — the monitor must start on the running kernel

The whole tool was dead. Nothing else about it can be observed, tested or trusted until
its BPF programs load and attach.

**Done when:** `NewProcessCollector()` returns without error on this kernel, and all
three of its tracepoints attach.

## Goal 2 — fork events must still carry pid, ppid and comm

Loading is necessary but not sufficient. The cheapest way to make the program load is
to delete the failing line — which would produce a program that loads happily while
silently reporting an empty `comm` on every fork event.

A fix that trades a load failure for silent data loss is not a fix. The observable
contract of the fork handler has to be preserved, not just its ability to verify.

**Done when:** forking a child from a tracked process produces a FORK event whose
`Pid` is the child, whose `Ppid` is the forking task, and whose `Comm` is the name the
child inherited.

## Goal 3 — the originally blocked end-to-end validation must finally run

The [C1 open-flags fix](../fix-c1-open-flags/) was proven at the collector and
aggregator level, but never through the real binary, because the binary would not
start. That check was left explicitly outstanding.

**Done when:** the `monitor` binary traces a real `npm install` and writes a session
JSON reporting `write_processes > 0`, against pre-fix sessions that all report `0`.

## Explicit non-goals

- **Not** regenerating `bpf/vmlinux.h`. It is the underlying cause, but replacing it is
  a repo-wide change affecting all four BPF programs and would couple the source to one
  kernel version. See [05-why-this-approach.md](05-why-this-approach.md).
- **Not** fixing the remaining audit findings (C2, C3, C4 and the High items).
- **Not** fixing the two further defects discovered during this work. They are recorded
  in [07-findings-not-fixed.md](07-findings-not-fixed.md).
- **Not** re-capturing the historical `sessions/*.json` corpus. That is a
  data-collection task; this change only unblocks it.
