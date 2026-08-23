# 1. Goals

## The defect

`AUDIT.md` H2, verbatim:

> `bpf/file_monitor.bpf.c` inserts into `pending_opens` at `sys_enter_openat`
> (keyed by `pid_tgid`) and only removes the entry in `sys_exit_openat`. If a
> process is SIGKILLed while blocked inside `openat`, `sys_exit_openat` never
> fires and the entry is never removed. The map is bounded (4096 entries) and
> `bpf_map_update_elem`'s return value is never checked at the insert site, so
> under sustained leakage the map silently starts dropping new file events
> with no signal to userspace.

Verified by reading, not assumed:

- `sys_enter_openat` (`file_monitor.bpf.c:203`, pre-fix) calls
  `bpf_map_update_elem(&pending_opens, &pid_tgid, &po, BPF_ANY)` and discards
  the return value unconditionally.
- `sys_exit_openat` (`file_monitor.bpf.c:232`, pre-fix) is the *only* code
  path that ever calls `bpf_map_delete_elem(&pending_opens, &pid_tgid)`.
  Grepped the file for other callers: none.
- `pending_opens` is `BPF_MAP_TYPE_HASH`, `max_entries = 4096` — a bounded
  resource, not a ring buffer that recycles itself.

This is two independent claims bundled into one finding, and they needed two
independent fixes:

1. **The insert-failure signal is missing.** If the map is ever full, the
   next tracked `openat()`'s insert silently fails and that open's
   `file_event` can never be emitted (the exit probe's own lookup will miss).
2. **The claimed leak mechanism.** A process killed mid-syscall leaves an
   orphaned entry forever, because only the syscall's own exit probe ever
   removes it.

## Why this is next

C1–C4 (all four Critical findings) and the addendum's High findings
(filename sanitisation, silent write failures) are fixed. Of the audit's
original H1–H7, only H1 is closed (as a side effect of the C3 fix — see
[`../fix-c3-double-completion/07-findings-not-fixed.md`](../fix-c3-double-completion/07-findings-not-fixed.md)).
H2 is the next unaddressed item in audit order, is squarely a kernel-boundary
(eBPF) concern, and — like C2/C3 — describes a failure mode that only
manifests under exactly the conditions a long, high-throughput capture run
would eventually hit: a process that dies abnormally, or a burst of file
activity dense enough to fill a 4096-entry map.

## Goals

1. **Insert failures are counted, not silently swallowed.** A userspace
   reader must be able to tell that `pending_opens` filled up and events were
   lost.
2. **No `pending_opens` entry outlives the thread that inserted it**, even if
   that thread never returns from `openat()` through the normal exit path.
3. **Prove both under real load/run conditions** (root, real syscalls, a real
   killed process) — not by reasoning about the C code alone.
4. **Nothing else changes** — no other BPF program, no output schema, no
   Go-visible behavior for the ordinary (non-exhausted, non-killed) case.

## How we would know

- Goal 1 → a test that fills `pending_opens` to capacity, forces one more
  real tracked `openat()` to fail its insert, and asserts a userspace-visible
  counter increases.
- Goal 2 → a test that gets a real tracked process genuinely blocked inside
  `openat()`, kills it, and asserts the map holds no trace of it afterward.
- Goal 3 → both tests require root/CAP_BPF to load and attach BPF programs;
  neither test data is achievable with a mocked structure.
- Goal 4 → full repository suite, `-race` and under root; the three
  untouched BPF programs' compiled objects verified byte-identical to `HEAD`.

## eBPF/kernel-specific test notes

Both new tests require an actual load and run against the real kernel
(root/`CAP_BPF`), not just verifier/compile-level acceptance — they assert on
live map contents (`pending_opens`, `file_monitor_stats`) after real syscalls
and a real `SIGKILL`, which no static check can substitute for. No kernel
version constraint beyond what the rest of this project already requires
(CO-RE/BTF support, already exercised by every other root-gated test in
`internal/collector`).
