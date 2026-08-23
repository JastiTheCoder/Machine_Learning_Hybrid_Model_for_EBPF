# 3. What was done

One BPF source file changed, one regenerated object, one new test file, and one
existing test file tightened.

## `bpf/process_tracer.bpf.c`

```diff
 SEC("tp/sched/sched_process_fork")
 int tracepoint__sched__sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
 {
-    __u32 parent_pid = (__u32)ctx->parent_pid;
-    __u32 child_pid  = (__u32)ctx->child_pid;
+    __u32 child_pid = (__u32)ctx->child_pid;
     struct process_event *evt;
 
+    /* tracked_pids is keyed by thread-group id everywhere else in this
+     * program and in every sibling BPF file ...
+     *
+     * ctx->parent_pid is NOT that: it is the calling *task's* pid, i.e. its
+     * thread id ... bpf_get_current_pid_tgid()>>32 gives the correct tgid
+     * regardless of which thread issued the syscall. */
+    __u64 pid_tgid   = bpf_get_current_pid_tgid();
+    __u32 parent_pid = (__u32)(pid_tgid >> 32);
+
     /* Only propagate tracking to children of already-tracked processes. */
     if (!is_tracked(parent_pid))
         return 0;
```

Nothing else in the function changed. `child_pid` — still read from
`ctx->child_pid` — is unaffected: it identifies the *new* task, and
`fork()`'s child is always a fresh thread-group leader, so `child_pid` is
already that child's own tgid regardless of which thread of the parent called
`fork()`. Only the parent-side lookup was wrong.

The full comment left in the source explains the mismatch, cites where the
tgid convention comes from (every sibling consumer of `tracked_pids`, and the
exit handler's own comment), and names the concrete motivating scenario — a
malicious script forking from a worker thread — so a future reader does not
have to reconstruct the reasoning from the diff alone.

## `internal/collector/processtracer_x86_bpfel.o`

Regenerated via `BPF2GO_STRIP=/usr/bin/strip go generate
./internal/collector/...`, which rebuilds all four BPF programs. The other
three objects came back byte-identical to their pre-regeneration checksums and
were restored with `git checkout --` where the working tree happened to differ
in byte layout from what was there before (`syscalltracer`, `tcpmonitor` —
their working-tree content matched `HEAD` exactly, so this was a safe,
verified restoration, not a blind revert). `processtracer_x86_bpfel.go` came
back byte-identical to its committed version — this fix changes control flow
inside the handler, not any struct layout — so only the `.o` differs.

Full checksum table: [`evidence/checksums.txt`](evidence/checksums.txt).

## `internal/collector/testdata/fork_from_thread.c` (new)

A ~60-line C program, described in [02-tests.md](02-tests.md). No third-party
dependencies — `pthread`, `unistd.h`, `sys/wait.h` from the standard library
only.

## `internal/collector/process_collector_test.go`

- Added `requireCC`, `compileForkFromThreadHelper`,
  `TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess`, and
  `parseHelperLine`.
- Removed `selfTaskIDs` (no longer used by anything).
- `TestProcessCollectorReportsForkOfTrackedProcess` now seeds `tracked_pids`
  with `os.Getpid()` alone instead of every thread id, with a comment
  explaining why the workaround it used to need is gone.

## Not changed

No other BPF program, no output format, no collector API. `AUDIT.md` is
updated to mark the finding fixed, matching the pattern of the previous three
tasks — see [06-results.md](06-results.md).
