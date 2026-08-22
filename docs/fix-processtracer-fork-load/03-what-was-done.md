# 3. What was done

Three files: one line of kernel logic, its recompiled artifact, and one test file.

| File | Status | Nature |
|------|--------|--------|
| `bpf/process_tracer.bpf.c` | modified | The fix — one statement replaced |
| `internal/collector/processtracer_x86_bpfel.o` | regenerated | Compiled output of the above |
| `internal/collector/process_collector_test.go` | modified | +2 tests, +3 helpers |

`processtracer_x86_bpfel.go` was regenerated but came out **byte-identical** to the
committed version — the change alters instructions, not the map/program surface bpf2go
describes. It is therefore not in the diff.

No other file was touched.

## 3.1 The fix — `bpf/process_tracer.bpf.c`

In `tracepoint__sched__sched_process_fork`, this:

```c
bpf_probe_read_kernel_str(evt->comm, sizeof(evt->comm), ctx->child_comm);
```

became this:

```c
/* Read comm from the current task rather than ctx->child_comm.
 *
 * This tracepoint fires inside copy_process() with current == the forking
 * task, and the child's comm is a copy of the parent's until it execs, so
 * both report the same string here.
 *
 * ctx->child_comm cannot be used portably: newer kernels declare
 * parent_comm/child_comm as __string() fields, which are stored as
 * __data_loc u32 descriptors rather than inline char[16] arrays.  CO-RE
 * cannot relocate a char[16] access onto that layout, so libbpf poisons
 * the instruction and the verifier rejects the program at load time.
 * The sibling exec and exit handlers already use this helper. */
bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
```

The comment is long on purpose. The line it replaces looks obviously correct, and
without an explanation the next person to read this file has every reason to "fix" it
back.

**This makes the fork handler consistent with its siblings.** `bpf_get_current_comm()`
is already used at `process_tracer.bpf.c:121` (exec handler) and `:266` (exit handler).
The fork handler was the only one of the three reading comm out of the tracepoint
context — the fix removes an inconsistency rather than introducing a special case.

Nothing else in the file needed changing. An audit of every `ctx->` access in
`process_tracer.bpf.c` found exactly five, and only this one was unresolvable:

| Line | Access | Context type | Status |
|------|--------|--------------|--------|
| 131 | `ctx->args[0]` | `trace_event_raw_sys_enter` | stable, fine |
| 132 | `ctx->args[1]` | `trace_event_raw_sys_enter` | stable, fine |
| 206 | `ctx->parent_pid` | `trace_event_raw_sched_process_fork` | relocates (24 → 12) |
| 207 | `ctx->child_pid` | `trace_event_raw_sched_process_fork` | relocates (44 → 20) |
| 224 | `ctx->child_comm` | `trace_event_raw_sched_process_fork` | **poisoned — fixed** |

The exit handler (`trace_event_raw_sched_process_template`) reads nothing from its
context at all.

## 3.2 The tests — `internal/collector/process_collector_test.go`

Appended to the existing file, which previously held only the layout guard:

- `TestNewProcessCollectorLoadsAndAttaches`
- `TestProcessCollectorReportsForkOfTrackedProcess`
- `requireRoot(t)` — skips unless euid 0, then removes the memlock rlimit
- `selfTaskIDs(t)` — every tid in `/proc/self/task`
- `selfComm(t)` — this process's comm, from `/proc/self/comm`
- `decodeComm(...)` — trims NUL padding from the fixed-width field

## 3.3 Regenerating the object

```
BPF2GO_STRIP=/usr/bin/strip GOPACKAGE=collector go generate ./internal/collector/...
```

`go generate` rebuilds **all four** BPF programs regardless of which source changed. The
three unrelated objects were restored immediately afterwards with a targeted
`git checkout --` on six specific paths, so the diff contains only the object that had
to change:

```
git checkout -- internal/collector/syscalltracer_x86_bpfel.{o,go} \
                internal/collector/tcpmonitor_x86_bpfel.{o,go}
```

(`filemonitor` was left as-is: it carries the C1 fix and regenerated to an identical
md5, confirming the build is deterministic.)

The `BPF2GO_STRIP=/usr/bin/strip` override is still required because `llvm-strip` is not
installed on this machine. That remains a workaround, not a fix — see
[05-why-this-approach.md](05-why-this-approach.md#on-the-strip-workaround).
