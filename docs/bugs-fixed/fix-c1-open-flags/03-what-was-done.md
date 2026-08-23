# 3. What was done

Six files changed: two production source files, one regenerated build artifact pair,
and three test files (two new).

| File | Status | Nature |
|------|--------|--------|
| `bpf/file_monitor.bpf.c` | modified | The actual fix (+6 / −1) |
| `internal/collector/filemonitor_x86_bpfel.o` | regenerated | Compiled output of the above |
| `internal/collector/filemonitor_x86_bpfel.go` | regenerated | bpf2go loader for the above |
| `internal/features/filetop_aggregator.go` | modified | `O_RDWR` classification |
| `internal/features/filetop_aggregator_test.go` | modified | +1 test |
| `internal/collector/file_collector_test.go` | **new** | +2 tests |
| `internal/features/filetop_npm_e2e_test.go` | **new** | +1 test |

No other file in the repository was touched.

## 3.1 The kernel-side fix — `bpf/file_monitor.bpf.c`

Three edits, all in service of one idea: `openat`'s flags exist only at *enter* time,
so they must be saved and carried to *exit* time.

**(a) Widen the transient state struct** to hold the flags:

```c
struct pending_open {
    __u32 pid;
    __u32 flags;          /* openat() flags captured at enter time */
    __u8  dir_category;
    __u8  pad[3];
};
```

**(b) Capture the flags in the enter probe**, where `ctx->args` is populated.
`args[2]` is `openat`'s third argument, `int flags`:

```c
struct pending_open po = {};
po.pid          = tgid;
po.flags        = (__u32)ctx->args[2];
po.dir_category = classify_dir(fname, len);
```

**(c) Emit them from the exit probe**, replacing the hardcoded zero:

```c
/* Open flags come from the enter probe: sys_exit_openat's context only
 * carries the return value, so args[2] is unavailable at this point. */
evt->flags = po->flags;
```

The `pending_opens` map, the enter/exit pairing, the `bpf_map_lookup_elem` of `po`,
and the `bpf_map_delete_elem` cleanup all already existed — `dir_category` was already
being ferried across the same boundary by the same mechanism. The fix adds one field
to an existing courier rather than introducing new machinery.

## 3.2 The userspace fix — `internal/features/filetop_aggregator.go`

```go
// A read-write open requests both capabilities, so an O_RDWR opener is
// counted as a reader *and* a writer.  O_CREAT implies the process is
// producing a file even when the access mode itself is read-only.
mode := event.Flags & syscall.O_ACCMODE
if mode == syscall.O_RDONLY || mode == syscall.O_RDWR {
    a.readPIDs[event.Pid] = true
}
if mode == syscall.O_WRONLY || mode == syscall.O_RDWR || (event.Flags&syscall.O_CREAT != 0) {
    a.writePIDs[event.Pid] = true
}
```

Only the read branch changed: `mode == syscall.O_RDONLY` became
`mode == syscall.O_RDONLY || mode == syscall.O_RDWR`. The write branch was already
correct.

## 3.3 What was explicitly *not* changed

- **`struct file_event` (C) and `FileEvent` (Go).** Neither needed to change. Both
  already had a `flags` field at offset 264. Test 2 now proves they agree.
- **`internal/collector/file_collector.go`.** The decode path was already correct.
- **The other three BPF programs.** `process_tracer`, `syscall_tracer` and
  `tcp_monitor` and their generated artifacts are byte-identical to what they were
  before this work. (They were regenerated at one point during the investigation and
  then restored from git, after regeneration was shown not to be the cause of the
  problem being chased — see [04-how-it-was-done.md](04-how-it-was-done.md#a-wrong-turn-and-how-it-was-undone).)
