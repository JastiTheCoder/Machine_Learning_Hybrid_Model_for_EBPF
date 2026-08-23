# 1. Goals

These were agreed **before** any test or code was written.

## Background: what was broken

`AUDIT.md` finding **C1 (Critical)** describes a defect that spans the kernel/userspace
boundary:

1. `bpf/file_monitor.bpf.c`, in `tracepoint__syscalls__sys_exit_openat`, set
   `evt->flags = 0` unconditionally before submitting each file event to the ring
   buffer.
2. `internal/features/filetop_aggregator.go` classifies each event with
   `mode := event.Flags & syscall.O_ACCMODE`.
3. On Linux `O_RDONLY == 0`. So `0 & O_ACCMODE == O_RDONLY`, and **every** open —
   including writes, creates and truncates — was classified as a read.

The consequences:

- `write_processes`, a required field of the QUT-DV25 feature schema this project
  exists to produce, was **always exactly 0**.
- `read_processes` was inflated to "every process that opened any file at all".
- Every session JSON in `sessions/` carries this defect, and so does every row of any
  CSV exported from them. Two of the 36 features fed to the Random Forest classifier
  were constants or noise.

## Goal 1 — open flags must survive the trip from kernel to userspace

A `FileEvent` delivered to Go must carry the actual `flags` argument that userspace
passed to `openat(2)`. This is the root cause; everything else is downstream.

**Done when:** a process opens a file with a known, distinctive flag combination and
a `FileEvent` carrying exactly those flags is observed on the Go side.

## Goal 2 — a read-write open must count as both a read and a write

Secondary correctness issue in the aggregator. `O_RDWR` requests both capabilities, so
the opening process is legitimately both a reader and a writer. The original code
credited `O_RDWR` to writers only, because its read branch tested `mode == O_RDONLY`
exclusively.

This mattered less while Goal 1 was broken (nothing reached the branch with real
flags), but it would have produced a *newly wrong* `read_processes` the moment Goal 1
was fixed.

**Done when:** a single `O_RDWR` open increments both `ReadProcesses` and
`WriteProcesses`.

> **Decision recorded:** counting `O_RDWR` as both was chosen deliberately over the
> alternative of counting it as write-only. See
> [05-why-this-approach.md](05-why-this-approach.md#why-o_rdwr-counts-as-both).

## Goal 3 — `write_processes` must be non-zero for a real `npm install`

The two goals above are mechanism. This one is the observable outcome the audit
finding is really about: `npm install` unpacks a package tree onto disk, so any honest
measurement must report at least one writing process.

**Done when:** a real `npm install` is traced end-to-end through the actual BPF
program and the real `FiletopAggregator`, and reports `write_processes > 0`.

## Goal 4 — the wire format must not silently drift again

The reason this bug survived so long is that the Go `FileEvent` struct and the C
`file_event` struct are two independent declarations of one binary layout, decoded
with `binary.Read`. Nothing checked that they agreed.

**Done when:** a test fails if the Go struct's size or field offsets change.

## Explicit non-goals

- **Not** fixing any other audit finding. C2, C3, C4 and the High findings are
  untouched.
- **Not** re-deriving `read_data_transfer_kb` / `write_data_transfer_kb` from real byte
  counts. The package doc already states these are approximations; that is a separate
  (and larger) piece of work.
- **Not** regenerating or re-labelling the existing `sessions/*.json` corpus. Those
  files were captured with the broken program and their `write_processes` values are
  not recoverable — they must be re-captured, which is a data-collection task, not a
  code task.
