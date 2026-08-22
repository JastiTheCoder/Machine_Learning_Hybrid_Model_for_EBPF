# 4. How it was done

## 4.0 Method

Same discipline as the [C1 fix](../fix-c1-open-flags/04-how-it-was-done.md): the TDD
skill at `skills/.agents/skills/tdd/`. Confirm the seams first; one test → one
implementation change; red before green; test through public interfaces with
independent expected values; refactoring is not part of the loop.

## 4.1 Establishing ground truth before writing anything

Four questions were answered from the code and the kernel, in this order, because each
one narrowed what the fix could be.

**Q1: Is the committed object stale relative to its source?**
`git diff --stat -- bpf/process_tracer.bpf.c` showed a file-mode change and zero content
changes. The `.o` and the `.c` agree, so regenerating would not silently pull in
unrelated uncommitted work.

**Q2: Which `ctx->` accesses can fail?**
Five in the file; the verifier log named the one at instruction 61. Cross-referencing
`grep -n 'ctx->'` against the three programs' context types confirmed the other four are
either stable syscall-entry fields or successfully relocated pids. **Exactly one line
needed to change** — established before touching anything.

**Q3: Who consumes `Comm` on fork events?**
This determined whether "just delete the line" was viable.

```
AddProcess()  ← the only thing that puts comm into output (ProcessTree)
  └── called only from attachExec()
        └── called only from handleExec()
```

So fork-event `Comm` reaches **only a `d.logf` debug line**, never a feature in the
session JSON. Deleting it would have cost almost nothing measurable.

**That finding argued for deletion. The fix preserves the data anyway** — see
[05-why-this-approach.md](05-why-this-approach.md#why-not-just-delete-the-line). The
point of asking was to know what was at stake, not to take the cheapest option.

**Q4: Is `bpf_get_current_comm()` actually equivalent here?**
From the kernel: `sched_process_fork` fires in `copy_process()` as
`trace_sched_process_fork(current, p)`, where `current` is the forking task and `p` is
the new child. `p` was duplicated from `current` and has not exec'd, so
`p->comm == current->comm`. Therefore `bpf_get_current_comm()` returns exactly what
`ctx->child_comm` holds.

This was treated as a hypothesis to be tested, not a fact to be asserted — which is what
Test 2's `Comm` assertion exists to settle.

## 4.2 Choosing the seams

Two seams, agreed up front:

1. **`NewProcessCollector()`** for "does it load". It is the public constructor
   `main.go` calls, and it covers verify + load + attach + ring-buffer-open in one call.
   The generated `LoadProcessTracer()` was rejected as a seam: it is bpf2go output, and
   asserting against it would neither survive regeneration nor catch an attach failure.

2. **`ProcessCollector.Events`** for "does it still report the right thing". Observing
   the actual event stream after an actual `fork()` is the only way to see what the
   handler emits. No mock can answer this — the code under test is the BPF program.

## 4.3 The slices

### Slice 1 — make it load

1. Wrote `TestNewProcessCollectorLoadsAndAttaches`. Ran as root. **Red**, with the
   poison error, confirming the failure at the seam rather than only in a log.
2. Wrote `TestProcessCollectorReportsForkOfTrackedProcess` in the same pass. **Red** at
   the same constructor call.

   Writing the second test *before* the fix was deliberate. Had the fix been applied
   first, the obvious minimal edit is to delete the failing line — and with only Test 1
   in place, that would have gone green while quietly emptying every fork event's comm.
   The constraining test has to exist before the temptation does.

3. Replaced the field read with `bpf_get_current_comm()`.
4. Regenerated the object; restored the three unrelated ones.
5. Re-ran. **Both green** — Test 1 in 0.21s, Test 2 in 0.63s with `Comm` matching
   `/proc/self/comm` exactly.

### Slice 2 — the end-to-end run

Not a code slice; the payoff. Covered in [06-results.md](06-results.md).

## 4.4 The TID/TGID detail

Test 2 initially seeded only the test process's pid into `tracked_pids`. Reading the
kernel's `TP_fast_assign` for this tracepoint showed why that is unreliable:

```c
__entry->parent_pid = parent->pid;   /* thread id, not thread-group id */
```

`tracked_pids` is keyed by tgid — the exec handler inserts `tgid`, and the exit handler's
comment says so explicitly. Go can run a fork from any runtime thread, so
`is_tracked(parent_pid)` may look up a tid that was never inserted.

The test now seeds every tid in `/proc/self/task`, which makes it independent of the
runtime's thread choice. **The underlying mismatch was left in place and recorded** as
[a finding](07-findings-not-fixed.md) — it is a different defect, and folding a
speculative fix for it into this change would have made both harder to review.

## 4.5 Verification performed

| Check | Command | Result |
|-------|---------|--------|
| Full suite, as root | `sudo -n /usr/bin/go test ./... -count=1` | all `ok` |
| Full suite, unprivileged, race | `go test -race ./... -count=1` | all `ok` |
| Vet | `go vet ./internal/collector/` | clean |
| Formatting | `gofmt -l` | changed file clean |
| Red reproduction | `git checkout` pre-fix `.o`, re-run | fails as expected |
| Monitor starts | `sudo -n /usr/bin/go run ./cmd/monitor` | reaches "active" |
| End-to-end | real `npm install` → session JSON | `write_processes: 1` |

Raw output in [`evidence/`](evidence/).
