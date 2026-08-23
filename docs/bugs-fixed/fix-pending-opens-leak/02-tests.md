# 2. Tests

Two new test functions in `internal/collector/file_collector_test.go`, both
root-gated, plus a small C fixture (`testdata/block_in_openat.c`) built for
one of them. A third, throwaway diagnostic test (not committed) is described
below because it changed what this document claims — it is exactly the kind
of thing the TDD skill's "checked for teeth" discipline exists to catch.

## Seams — agreed before any test was written

Two independent claims in H2, two independent seams:

| Seam | Outcome |
|---|---|
| A real, tracked `openat()` forced to fail its `pending_opens` insert | ✅ **the test with teeth** — genuinely reds pre-fix |
| A real, tracked process killed while genuinely blocked inside `openat()` | ⚠️ **an audit-correcting result** — see below |

## Slice 1 — `TestFileMonitorCountsFailedPendingOpensInserts`

Fills `pending_opens` to its 4096-entry bound with synthetic keys reserved
well outside any real `pid_tgid` range (`0xFFFFFFFF << 32 | i` — no live PID
can ever occupy the top 32 bits, since Linux's `pid_max` is far below
`0xFFFFFFFF`), then performs one real `openat()` from a process marked
tracked. With the map full, the kernel's own `sys_enter_openat` probe is now
guaranteed to have its `bpf_map_update_elem` call fail for real — not
simulated, not asserted by reading the C — and the test polls the new
`FileCollector.PendingOpensInsertFailures()` accessor for the count to rise.

**Result: achieved.** Red (`before=0, after=0` — the call failed but nothing
counted it) → green (count rises).

Raw: [`red-both-fix-lines-reverted.txt`](evidence/red-both-fix-lines-reverted.txt)
(the insert-check revert half of that run), full green in
[`full-collector-suite-green.txt`](evidence/full-collector-suite-green.txt).

## Slice 2 — `TestFileCollectorClearsPendingOpensEntryWhenKilledMidOpenat`, and the finding that reshaped it

The intended reproduction: get a real, tracked process genuinely blocked
inside `openat()`, `SIGKILL` it, and assert `pending_opens` holds no trace of
it afterward. `testdata/block_in_openat.c` makes "genuinely blocked" not a
matter of timing luck: it prints its own pid, waits for a handshake byte, then
calls `open()` on a FIFO with no writer — which blocks in an interruptible
sleep for as long as nothing opens the other end. Smoke-tested standalone
before being wired into Go (`timeout 2s` killed it, confirming it really
blocks).

Wrote the test, ran it against the reverted (pre-fix) `file_monitor.bpf.c`
expecting red. **It passed.** Rather than accept a first-try pass at face
value, it was checked for teeth — and the check changed the finding:

A throwaway diagnostic test confirmed why: on this kernel,
`sys_exit_openat`'s own tracepoint **still fires** for a process killed while
blocked in an interruptible sleep, with `ctx->ret` carrying the interrupted
return code (`open_success=0` was observed on the emitted `file_event`). H2's
literal premise — "`sys_exit_openat` never fires" — does not hold for this
scenario on this kernel. The pre-existing cleanup path was already handling
it.

This did not make the test worthless; it changed what needed proving.
Three follow-up isolation runs, each rebuilding just the one `.bpf.c` and
re-running this one test:

| Configuration | Result |
|---|---|
| Both cleanup paths (`sys_exit_openat`'s two deletes, and the new hook) disabled | **FAILS** — the entry genuinely leaks |
| Only the new `sched_process_exit` hook enabled | **PASSES** — sufficient alone |
| Only the pre-existing `sys_exit_openat` cleanup enabled | **PASSES** — sufficient alone |

This proves three things at once: the map *can* genuinely leak (so the
underlying concern in H2 is real, even though the specific SIGKILL-while-
interruptibly-blocked path already self-heals), and either cleanup path
independently closes it. The new hook is retained as a backstop for exactly
the case that isn't self-healing: a thread that dies without ever returning
from `openat()` at all — e.g. blocked in an *uninterruptible* (D-state) wait
on an unresponsive filesystem, which `SIGKILL` cannot unblock until the I/O
itself resolves. That scenario is real (any hung NFS mount or misbehaving
FUSE server produces it) but not reproducible portably in this test
environment without a custom, unresponsive filesystem server — out of
proportion to what this fix needs.

**Result: the property holds (no leaked entry after a killed process,
confirmed under the reproducible scenario), but the mechanism differs from
what the audit assumed.** Both the test and its doc comment say so explicitly,
per the same discipline used for the seam that didn't work in
[`../fix-c2-buildrecord-race/`](../fix-c2-buildrecord-race/) and the guard
without teeth in [`../fix-c3-double-completion/`](../fix-c3-double-completion/).

Raw:
[`red-all-cleanup-paths-disabled.txt`](evidence/red-all-cleanup-paths-disabled.txt),
[`isolation-new-hook-alone-sufficient.txt`](evidence/isolation-new-hook-alone-sufficient.txt),
[`isolation-old-path-alone-sufficient.txt`](evidence/isolation-old-path-alone-sufficient.txt).

---

## Goal coverage

| Goal | Covered by | Achieved |
|---|---|---|
| 1 — insert failures counted | Slice 1 | yes |
| 2 — no entry outlives its thread | Slice 2, for the reproducible case; the new hook is a documented backstop for the unreproduced D-state case | partial, honestly stated |
| 3 — proven under real load/run | Both slices require root and load real BPF programs | yes |
| 4 — nothing else changes | Full `-race` + root suites; three untouched `.o`/`.go` pairs byte-identical to `HEAD` | yes |
