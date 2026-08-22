# 7. Out of scope — ProcessTracer will not load on this kernel

Found while trying to validate the C1 fix through the real `monitor` binary.
**Not fixed here.** Documented so it can be picked up deliberately.

Severity: **Critical** — the monitor cannot start at all.

## Symptom

```
$ sudo -n /usr/bin/go run ./cmd/monitor -output-dir ... -session-timeout 30s
load ProcessTracer: load ProcessTracer objects:
  field TracepointSchedSchedProcessFork:
  program tracepoint__sched__sched_process_fork:
  load program: invalid argument: invalid func unknown#195896080
exit status 1
```

## This is pre-existing, not a regression

Initially assumed to be fallout from regenerating the BPF objects during this work. It
is not. The three unrelated objects were restored to their exact committed state
(`git checkout --`) and **the error reproduced identically**. The committed
`processtracer_x86_bpfel.o` does not load on this kernel.

## Root cause

`195896080` is `0x0BAD2310`. That is cilium/ebpf's poison value for a **failed CO-RE
relocation** — `btf/core.go:44`:

```go
if f.poison {
    const badRelo = 0xbad2310
    *ins = asm.BuiltinFunc(badRelo).Call()
}
```

When a CO-RE field access cannot be resolved against the running kernel's BTF, the
library replaces the instruction with a call to a nonexistent helper. The verifier
rejects it if the instruction is reachable — which here it is.

The failing access is `ctx->child_comm`. The repo's `bpf/vmlinux.h` declares:

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

The running kernel (6.x+, this machine reports `7.1.5-arch1-2`) actually has:

```
size=24
  offset=0    ent                     struct trace_entry
  offset=8    __data_loc_parent_comm  u32
  offset=12   parent_pid              pid_t
  offset=16   __data_loc_child_comm   u32
  offset=20   child_pid               pid_t
  offset=24   __data                  char[0]
```

Upstream converted this tracepoint's `__array(char, comm, TASK_COMM_LEN)` fields to
`__string(...)`, which stores them as dynamic `__data_loc` u32 descriptors in the
trailing `__data` region instead of inline 16-byte arrays.

Consequences:

- `parent_pid` and `child_pid` **do** relocate — CO-RE finds them by name and rewrites
  the offsets from 24/44 to 12/20. The verifier log confirms this: `r9 = *(u32 *)(r6 +20)`
  and `r8 = *(u32 *)(r6 +12)`.
- `child_comm` **does not exist** as a field of that name and type. There is no
  `char[16]` to point at. The relocation is poisoned, and the program dies at
  instruction 61 — the `bpf_probe_read_kernel_str(evt->comm, ..., ctx->child_comm)`
  call site.

Full verifier output: [`evidence/processtracer-verifier.log`](evidence/processtracer-verifier.log).

The underlying problem is that `bpf/vmlinux.h` is a stale dump from an older kernel.
This is precisely the failure mode CO-RE is meant to absorb — and it does, for field
*offsets*. It cannot absorb a field that has changed *kind*.

## Why the C1 work was still validated

The `file_monitor` program is unaffected (it does not touch this struct) and loads,
attaches and runs correctly. The end-to-end test therefore drives `FileCollector` and
`FiletopAggregator` directly, seeding `tracked_pids` by walking `/proc` for descendants
of the npm process — doing in the test what ProcessTracer's fork propagation would
normally do. Every layer specific to C1 is exercised against the real kernel; only the
process-tree plumbing is substituted.

## Suggested fixes, cheapest first

1. **Drop the `comm` read from the fork handler.** The fork event's `comm` is the
   child's *pre-exec* name — almost always a copy of the parent's — and
   `tracepoint__syscalls__sys_enter_execve` sets the meaningful name moments later.
   Deleting the `bpf_probe_read_kernel_str(evt->comm, ...)` line removes the failing
   relocation. Smallest possible change; verify nothing downstream depends on `comm`
   being populated on `event_type == 1` events.

2. **Regenerate `vmlinux.h`** from this kernel
   (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`) and read `child_comm`
   through the `__data_loc` descriptor. Correct, but couples the source to the newer
   layout and will break on older kernels unless guarded with
   `bpf_core_field_exists()`.

3. **Handle both layouts** with `bpf_core_field_exists(ctx->child_comm)` and a
   `__data_loc` fallback. Most portable, most code.

Recommendation: **(1)**, unless `comm` on fork events is actually consumed somewhere.

## Verify any fix with

```
sudo -n /usr/bin/go test ./internal/collector/ -count=1
sudo -n /usr/bin/go run ./cmd/monitor -output-dir /tmp/out -session-timeout 30s
```

The second command must reach its "monitoring" state instead of exiting 1. Once it
does, the C1 fix can finally be confirmed in a written session JSON — the check that
matters is `write_processes` being non-zero in the emitted file.
