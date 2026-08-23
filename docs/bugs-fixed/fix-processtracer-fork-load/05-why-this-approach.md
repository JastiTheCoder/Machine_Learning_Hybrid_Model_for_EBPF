# 5. Why it was done this way

Three real alternatives existed. This records what was chosen and what was given up.

## The candidates

The blocker write-up proposed three fixes, cheapest first:

1. Delete the `comm` read from the fork handler.
2. Regenerate `vmlinux.h` and decode the `__data_loc` descriptor.
3. Handle both layouts with `bpf_core_field_exists()` and a fallback.

**A fourth was chosen instead: `bpf_get_current_comm()`.** It costs the same as (1),
preserves the data like (2) and (3), and is portable across every kernel without
conditionals.

## Why not just delete the line

This was the recommended option in the original analysis, and the investigation
strengthened the case for it: fork-event `Comm` reaches only a `d.logf` debug line.
`AddProcess()` — the only path that puts a comm into the session JSON's `process_tree` —
is called exclusively from the exec path. Deleting the read would have cost one debug
log field and nothing measurable.

**Rejected anyway**, for two reasons.

First, the cost of the alternative is one helper call. When preserving the data is that
cheap, "nothing important reads it *today*" is a weak argument — it silently converts a
populated field into a permanently empty one, and the next person to use `comm` on a
fork event gets an empty string with no indication why.

Second, and more practically: the fork handler's `d.logf` line is exactly the diagnostic
you reach for when debugging why a session did not attach a child process. Blanking it
degrades the tool precisely where it is most needed.

The general principle: deleting a field read is a change to the program's *output
contract*, dressed up as a change to its *implementation*. Preserving the contract for
one extra instruction is the better trade.

## Why not decode `__data_loc`

Decoding the descriptor by hand is entirely doable — the u32 packs length in the high
16 bits and a ctx-relative offset in the low 16:

```c
__u32 dl  = ctx->__data_loc_child_comm;
char *src = (char *)ctx + (dl & 0xFFFF);
bpf_probe_read_kernel_str(evt->comm, sizeof(evt->comm), src);
```

**Rejected because it inverts the portability problem rather than solving it.** That
code requires the *new* layout, so it breaks on the older kernels the current
`vmlinux.h` describes. It also requires regenerating `vmlinux.h` — a 100k-line
generated header shared by all four BPF programs — turning a one-line fix into a
repo-wide change with a much larger blast radius, on a component nobody asked to have
touched.

It also hard-codes a kernel-internal encoding into application code, which is precisely
the class of thing CO-RE exists to avoid.

## Why not `bpf_core_field_exists()` with a fallback

The most rigorous option: detect which layout the running kernel has and read
accordingly. Genuinely portable, and the right answer if the field's value were
irreplaceable.

**Rejected because it is the most code and buys nothing here.** It still needs the
regenerated `vmlinux.h` to name the `__data_loc` field, still hard-codes the
descriptor encoding, and adds a branch — all to obtain a string that a single existing
helper already returns correctly on every kernel.

Complexity is justified by necessity, not by thoroughness. Here there is a simpler path
to the identical result.

## Why `bpf_get_current_comm()` is correct, not merely convenient

The equivalence is a property of where the tracepoint fires, not a coincidence:

- `sched_process_fork` is raised inside `copy_process()` as
  `trace_sched_process_fork(current, p)`.
- `current` is the forking task; `p` is the newly created child.
- The tracepoint records `child_comm` as `p->comm`.
- `p` was duplicated from `current` and has not yet exec'd, so `p->comm == current->comm`.

Therefore `bpf_get_current_comm()` returns exactly the string `ctx->child_comm` holds.

This was treated as a hypothesis, not a conclusion. Test 2 asserts the reported comm
equals `/proc/self/comm` read independently before the fork, so the equivalence is
verified on this kernel rather than argued for.

Three further points in its favour:

1. **Zero relocations.** `bpf_get_current_comm` is a stable helper (id 16), present
   since Linux 4.2. It cannot be poisoned by a BTF mismatch, so this class of failure
   cannot recur here.
2. **Already proven in this exact program.** The exec handler (line 121) and exit
   handler (line 266) both use it. The fork handler was the outlier; the fix removes an
   inconsistency rather than adding a special case.
3. **Independent of `vmlinux.h`.** The stale header remains stale, but this program no
   longer depends on the part of it that rotted.

## What this fix does *not* address

`bpf/vmlinux.h` is still a stale dump from an older kernel, and that is still the root
cause. This change removes the *one* dependency on the part that has diverged; it does
not make the header correct.

That was a deliberate scope decision, not an oversight. Regenerating `vmlinux.h` affects
all four BPF programs and would need every one of them re-verified against both old and
new kernels — a substantially larger piece of work than the defect being fixed, and one
worth doing deliberately rather than as a side effect. The risk of leaving it is
bounded and now known: any *future* access to a tracepoint field whose kind has changed
will fail the same way, with the same recognisable `0xBAD2310` signature.

## On the `strip` workaround

Regeneration still requires `BPF2GO_STRIP=/usr/bin/strip` because `llvm-strip` is absent.
Unchanged from the C1 work, and still the recommendation: install the LLVM binutils and
wire the `Makefile`'s already-pinned `clang-14`/`llvm-strip-14` into the generate step,
which fixes a standing audit finding at the same time.

## Why the end-to-end check was manual

The monitor is a privileged, long-running daemon that attaches system-wide tracepoints
and flushes sessions on a timer. Wrapping it in `go test` would mean spawning a
privileged subprocess, watching a log for readiness, driving npm, and waiting out a
session timeout — a slow test with many failure modes unrelated to what it asserts.

The two unit-level tests already pin the behaviour that can regress silently. The
end-to-end run answers a question that is asked once per change — "does the binary
work?" — and is better served by a recorded, reproducible procedure than by a flaky
test. The procedure and its artefacts are in [06-results.md](06-results.md) and
[`evidence/`](evidence/).
