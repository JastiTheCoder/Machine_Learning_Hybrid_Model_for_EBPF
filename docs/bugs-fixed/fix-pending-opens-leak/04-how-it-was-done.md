# 4. How it was done

## Step 0 — verify the audit's claims rather than trust them

Read `sys_enter_openat` and `sys_exit_openat` in full. Confirmed directly:
the insert's return value was discarded (`bpf_map_update_elem(...)` as a bare
statement), and grepping the file for `bpf_map_delete_elem(&pending_opens`
found exactly the two call sites inside `sys_exit_openat` — no other cleanup
path exists anywhere in the file.

## Step 0b — confirm seams and the fix approach

Two seams (insert-failure counting; kill-mid-syscall cleanup) and the fix
shapes (a stats array map; a new `sched_process_exit` tracepoint) were
settled before writing any test, per the TDD skill's requirement.

## Slice 1 — the counter

**Red**, against the unmodified insert site:

```
file_collector_test.go:340: file_monitor_stats[pending_opens insert failed]
    did not increase (before=0, after=0) after a real openat() with
    pending_opens full; the failed insert went uncounted (AUDIT.md H2)
--- FAIL: TestFileMonitorCountsFailedPendingOpensInserts
```

**Green:** added `file_monitor_stats` and the `count_stat` helper, checked
the insert's return value. Re-ran: count rises after the forced-full insert.

## Slice 2 — the cleanup hook, and the detour that mattered most

**Implemented first, tested second** for this slice specifically — the fix
(the new tracepoint) was written together with slice 1's fix, since both live
in the same file and were reasoned about together in step 0b. The test was
then written against the *reverted* code to get a red, as slice 1's was.

**First surprise:** it passed against the revert.

```
--- PASS: TestFileCollectorClearsPendingOpensEntryWhenKilledMidOpenat (0.60s)
```

Per this project's established discipline (a guard that passes on the first
run proves nothing until you know it can fail — see
[`../fix-c3-double-completion/05-why-this-approach.md`](../fix-c3-double-completion/05-why-this-approach.md)),
this was investigated rather than accepted. A throwaway diagnostic test
(not committed) instrumented the same scenario and logged every `FileEvent`
received after the kill:

```
entry present before kill
got FileEvent pid=40429 open_success=0
saw file_event for helper after SIGKILL: true
pending_opens lookup after kill+1s: lookup: key does not exist
```

`sys_exit_openat`'s own probe fired, with `open_success=0` reflecting the
interrupted return code, and cleaned up the entry itself — on this kernel,
for a `SIGKILL` delivered during an interruptible sleep, H2's literal premise
does not hold. This is an audit-correcting empirical finding, not a
test-writing mistake.

**Isolation, not abandonment.** Rather than drop the scenario, three
follow-up builds isolated which path was actually responsible, each rebuilding
only `file_monitor.bpf.c` (map/program declarations kept identical so the Go
bindings never needed to change) and re-running the one test:

1. Both `sys_exit_openat`'s deletes *and* the new hook disabled (a `// BUG-FOR-RED`/`// ISOLATION-CHECK`-commented `return 0` in place of each):

   ```
   file_collector_test.go:260: pending_opens still holds an entry for killed
       pid 42724 2s later; the entry leaked (AUDIT.md H2)
   --- FAIL: TestFileCollectorClearsPendingOpensEntryWhenKilledMidOpenat
   ```

   Confirms the map *can* genuinely leak — the underlying concern in H2 is
   real, independent of which specific kill scenario reproduces it.

2. Only the new hook enabled (old path still disabled): **PASS.** The new
   hook alone is sufficient.

3. Only the old `sys_exit_openat` path enabled (new hook disabled): **PASS.**
   Confirms what the diagnostic already showed — this path was already
   sufficient for this exact scenario, pre-fix.

Each configuration change was a source edit plus
`BPF2GO_STRIP=/usr/bin/strip go run .../bpf2go -target amd64 FileMonitor
../../bpf/file_monitor.bpf.c` (invoked directly rather than via `go
generate` for this narrower loop, to avoid needlessly rebuilding the other
three programs on every isolation step — `GOPACKAGE=collector` set
explicitly since the directive isn't present outside `//go:generate`).

Raw:
[`red-all-cleanup-paths-disabled.txt`](evidence/red-all-cleanup-paths-disabled.txt),
[`isolation-new-hook-alone-sufficient.txt`](evidence/isolation-new-hook-alone-sufficient.txt),
[`isolation-old-path-alone-sufficient.txt`](evidence/isolation-old-path-alone-sufficient.txt).

## Step — restore the fix and confirm bindings are unaffected

```
$ cp <saved fixed file_monitor.bpf.c> bpf/file_monitor.bpf.c
$ diff bpf/file_monitor.bpf.c <saved> && echo "restored exactly"
restored exactly
$ BPF2GO_STRIP=/usr/bin/strip go run .../bpf2go -target amd64 FileMonitor ../../bpf/file_monitor.bpf.c
$ md5sum internal/collector/filemonitor_x86_bpfel.go <saved .go>
bcc038c4ee84538ae9b67440ae50ad2f  (both) -- identical
```

## Step — regenerate for real, and account for every object bpf2go touches

```
$ BPF2GO_STRIP=/usr/bin/strip go generate ./internal/collector/...
```

Rebuilds all four programs regardless of which `.bpf.c` changed — the
documented gotcha from earlier fixes. Checked each of the other three:

- `.go` bindings (`processtracer`, `syscalltracer`, `tcpmonitor`) came back
  byte-identical to `HEAD` — no struct/program-name changes, as expected
  since their sources are untouched.
- `.o` objects for `syscalltracer`/`tcpmonitor` came back with *different*
  bytes than `HEAD`, despite identical bindings and untouched sources —
  bpf2go's build is not fully byte-deterministic across separate invocations
  (BTF/section-ordering artifacts, not semantic content). `processtracer_x86_bpfel.o`
  happened to match. All three `.o` files were confirmed to have matching
  `HEAD` counterparts available (verified before regenerating, so `git
  checkout --` was known-safe rather than assumed-safe) and restored.
- `filemonitor_x86_bpfel.{o,go}` differ, as intended — this is the fix.

Raw: [`checksums.txt`](evidence/checksums.txt).

## Step — the real binary, and a fix along the way

```
$ sudo -n /usr/bin/go run ./cmd/monitor -dry-run
  ✓ FileMonitor        → tracepoint/syscalls/sys_enter_openat, sys_exit_openat
  All probes loaded successfully.
```

Loaded and attached correctly (confirmed by "All probes loaded successfully"
and no error against `FileMonitor`), but the printed description only named
two of the three tracepoints `NewFileCollector` now attaches — a hardcoded
string, unrelated to the actual attach calls, that had gone stale the moment
the third tracepoint was added. Fixed it to name all three, then reran to
confirm:

```
  ✓ FileMonitor        → tracepoint/syscalls/sys_enter_openat, sys_exit_openat, sched_process_exit
```

Raw: [`dry-run-attachment.txt`](evidence/dry-run-attachment.txt).

## Step — verify the whole repository

```
$ go build ./...                                          BUILD OK
$ go vet ./...                                             clean
$ go test -race ./... -count=1                             all ok (9 packages)
$ sudo -n /usr/bin/go test ./... -count=1                  all ok (9 packages)
$ sudo -n /usr/bin/go test ./internal/collector/... -v -count=3 \
    -run 'TestFileCollectorClearsPendingOpensEntryWhenKilledMidOpenat|TestFileMonitorCountsFailedPendingOpensInserts'
                                                            3/3 clean runs, zero flakes
```

Raw: [`race-suite.txt`](evidence/race-suite.txt),
[`root-suite.txt`](evidence/root-suite.txt),
[`full-collector-suite-green.txt`](evidence/full-collector-suite-green.txt),
[`repeat-runs-green.txt`](evidence/repeat-runs-green.txt).
