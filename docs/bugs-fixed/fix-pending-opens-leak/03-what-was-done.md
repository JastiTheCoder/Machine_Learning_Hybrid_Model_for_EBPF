# 3. What was done

One BPF source changed, one collector wired up the new tracepoint and a
counter accessor, one call site in `cmd/monitor` reports the counter at
shutdown, one new test file's worth of tests, one new C fixture.

## `bpf/file_monitor.bpf.c` — the two fixes

**1. Count failed inserts.** A new single-counter array map, and the insert
site now checks its own return value:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} file_monitor_stats SEC(".maps");

#define STAT_PENDING_OPENS_INSERT_FAILED 0

static __always_inline void count_stat(__u32 index)
{
    __u64 *counter = bpf_map_lookup_elem(&file_monitor_stats, &index);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}
```

```diff
-    bpf_map_update_elem(&pending_opens, &pid_tgid, &po, BPF_ANY);
-    return 0;
+    if (bpf_map_update_elem(&pending_opens, &pid_tgid, &po, BPF_ANY) != 0)
+        count_stat(STAT_PENDING_OPENS_INSERT_FAILED);
+    return 0;
```

**2. Clean up on thread exit.** A new tracepoint, attached independently of
`process_tracer.bpf.c`'s own `sched_process_exit` handler (a separate BPF
program in a separate object; both can attach to the same kernel tracepoint):

```c
SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);

    if (!is_tracked(tgid))
        return 0;

    bpf_map_delete_elem(&pending_opens, &pid_tgid);
    return 0;
}
```

Unlike `process_tracer.bpf.c`'s handler — which only acts when the
thread-group leader exits, because `tracked_pids` is keyed by tgid alone —
this one does **not** filter to the leader. `pending_opens` is keyed by the
full `pid_tgid` of whichever thread called `openat()`, so any exiting thread
of a tracked process may have its own entry to clean up. The doc comment on
the tracepoint spells out this asymmetry explicitly, since it is the one
detail most likely to be "fixed" incorrectly by a future reader pattern-
matching on the sibling file.

## `internal/collector/file_collector.go` — attach and expose

`FileCollector` gained a third `link.Link` (`linkProcessExit`), attached and
torn down alongside the existing two, and one new accessor:

```go
// PendingOpensInsertFailures returns how many times inserting into the
// pending_opens map has failed since this collector was loaded -- almost
// always because the map was at its 4096-entry bound.
func (c *FileCollector) PendingOpensInsertFailures() (uint64, error) {
	var count uint64
	key := uint32(0)
	if err := c.objs.FileMonitorStats.Lookup(&key, &count); err != nil {
		return 0, fmt.Errorf("lookup file_monitor_stats[0]: %w", err)
	}
	return count, nil
}
```

`NewFileCollector` now attaches `sched/sched_process_exit` as a third
tracepoint alongside the existing two, unwinding all three on any attachment
failure exactly as the existing two already did. `Close()` closes all three
links.

## `cmd/monitor/main.go` — surface the counter, and fix a stale status string

At shutdown, after `wg.Wait()` but *before* closing the file collector (which
releases the map FD this counter reads from):

```go
pendingOpensLost, pendingOpensLostErr := fileCollector.PendingOpensInsertFailures()
// ...close all collectors...
if pendingOpensLostErr != nil {
    log.Printf("read pending_opens insert-failure counter: %v", pendingOpensLostErr)
} else if pendingOpensLost > 0 {
    log.Printf("%d file-open event(s) were dropped: pending_opens filled to its "+
        "4096-entry bound during this run", pendingOpensLost)
}
```

This mirrors the existing `LOST %d of %d session(s)` shutdown line added for
the silent-write-failures fix — the same "count it, report it at shutdown,
never fail silently" shape.

`runDryRun`'s `FileMonitor` status line was a hardcoded description of which
tracepoints `NewFileCollector` attaches (`"tracepoint/syscalls/sys_enter_openat,
sys_exit_openat"`); it now also names `sched_process_exit`, matching what the
function it describes actually attaches. This line is not decorative — a dry
run's entire purpose is confirming attachment, so a description missing one of
three attached programs would be actively misleading about what was checked.

## `internal/collector/testdata/block_in_openat.c` — new test fixture

Prints its own pid, waits for a one-byte handshake on stdin, then blocks in
`open(argv[1], O_RDONLY)` — deterministic when `argv[1]` is a FIFO with no
writer. Compiled fresh per test run via the existing `requireCC` helper,
matching the pattern already used for `fork_from_thread.c`.

## Test files

- `internal/collector/file_collector_test.go` — added
  `TestFileCollectorClearsPendingOpensEntryWhenKilledMidOpenat`,
  `TestFileMonitorCountsFailedPendingOpensInserts`,
  `compileBlockInOpenatHelper`, and `pendingOpenValue` (a Go mirror of
  `struct pending_open`, used only to give `ebpf.Map.Put`/`Lookup` a value of
  the right size).

No existing test was modified.

## Not changed

No change to `process_tracer.bpf.c`, `syscall_tracer.bpf.c`, or
`tcp_monitor.bpf.c` — their compiled objects (`.o`) and generated bindings
(`.go`) were regenerated as an unavoidable side effect of `go generate`
touching all four programs, then verified byte-identical to `HEAD` and
restored via `git checkout --` where bpf2go's non-deterministic build
metadata (not the C source) produced different bytes. No output schema, no
session/detector code, no other collector's behavior.
