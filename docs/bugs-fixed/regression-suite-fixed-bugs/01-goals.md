# 1. Goals

## The request

Not an `AUDIT.md` finding this time, but an explicit instruction: write new
tests, following the TDD skill, that (a) exercise the overall execution of
the program accounting for every bug fixed so far, (b) formally evaluate the
validity of every fix implemented to date, (c) take into account the
sub-bugs each fix's own investigation discovered along the way and test
those too, and (d) document and fix anything that fails.

## Verified starting point — what already exists, read before writing anything

Twelve fixes exist in `docs/bugs-fixed/` as of this task: `fix-c1-open-flags`,
`fix-c2-buildrecord-race`, `fix-c3-double-completion`,
`fix-c4-ground-truth-labels`, `fix-collector-drop-counting` (H5),
`fix-dead-detector-run` (H3), `fix-fork-tgid-lookup`,
`fix-output-filename-sanitization`, `fix-pending-opens-leak` (H2),
`fix-processtracer-fork-load`, `fix-route-drop-counting` (H4), and
`fix-silent-write-failures`. Each was read in full (README plus
`07-findings-not-fixed.md` at minimum) before any code was written, to build
an accurate picture rather than guess:

- Every one of the twelve already ships its own tests, each pinned at that
  fix's own narrow seam (one collector's `Events` channel, one BPF map, one
  detector method). None of them run the compiled `monitor` binary itself.
- Several fixes' own investigations surfaced further, real sub-bugs *while
  fixing the named finding* — not hypothetical, not copied from `AUDIT.md`'s
  original list:
  - `fix-c1-open-flags` discovered ProcessTracer could not load on this
    kernel at all (`07-out-of-scope-blocker.md`) — later fixed by
    `fix-processtracer-fork-load`.
  - `fix-processtracer-fork-load` discovered two further defects
    (`07-findings-not-fixed.md`): session files silently lost for
    path-like/scoped package specs (Finding 1, later fixed by
    `fix-output-filename-sanitization`), and a tid-vs-tgid mismatch in the
    fork handler's lookup (Finding 2, later fixed by `fix-fork-tgid-lookup`).
  - `fix-fork-tgid-lookup`'s own `07-findings-not-fixed.md`, item B, states
    plainly that its fix was demonstrated only via a synthetic C fixture
    forking from a non-leader pthread — never through a real npm install
    running a real node child process, "the motivating real-world scenario."
  - `fix-silent-write-failures`'s own `07-findings-not-fixed.md`, item A,
    states plainly that its exit-code behavior was never verified end to
    end, because the sudo grant available at the time covered only the `go`
    binary and a root-owned monitor process could not be signalled from an
    unprivileged session.
  - `fix-collector-drop-counting` (H5, the immediately preceding task in
    this series) discovered and fixed a real test deadlock in
    `ProcessCollector`'s own test mid-task.

  All of the *fixed* sub-bugs above are themselves already covered by their
  own fix's unit tests. What none of them have is a test proving the whole
  chain works together, through the actual binary, the way an operator
  actually runs it — and two of them (fork-tgid-lookup's item B,
  silent-write-failures' item A) are named, in writing, as verification gaps
  nobody had closed yet.

## Goals

1. **A whole-program seam, not another unit seam.** New tests must drive the
   compiled `cmd/monitor` binary (and, where relevant, `cmd/dataset/labeler`)
   as real subprocesses against real npm installs — the "overall execution
   of the program" the request asks for, distinct from the many existing
   collector/detector-level tests.
2. **Close the two named, still-open verification gaps** where the tooling
   available now makes it possible: fork-tgid-lookup's real-npm-child-process
   gap (item B) and silent-write-failures' real-signal-and-exit-status gap
   (item A) — the latter was blocked at the time by a sudo/signal limitation
   this task's own test architecture (running entirely inside a root-owned
   `go test` process) removes.
3. **Run the whole existing suite alongside the new tests, not just the new
   tests in isolation**, per this project's own established discipline (the
   H5 fix's `ProcessCollector` deadlock was invisible in isolation and only
   found by running everything together). Any red found this way gets
   documented and fixed, per the task's own instruction — not silently
   worked around.
4. **Do not re-litigate deliberately-deferred findings.** Every fix's
   `07-findings-not-fixed.md` also lists items explicitly deferred *by
   design*, with reasoning already on record (e.g. C2's item B on
   `RouteToSession`'s lock-release contract, fork-tgid-lookup's item A on
   the `CLONE_THREAD` insert-side gap, C4's items A/B/C/D/E on schema
   scope). Those are re-confirmed still-accurate in
   [07-findings-not-fixed.md](07-findings-not-fixed.md), not reopened —
   fixing them was never what this task's instruction asked for, and
   `CLAUDE.md`'s own scope discipline argues against a drive-by sweep of
   twelve fixes' worth of deferred, reasoned-through decisions.

## How we would know

- Goal 1 → `cmd/monitor/e2e_regression_test.go` exists, drives real
  binaries, real npm, real BPF.
- Goal 2 → a test that starts real npm, installs a package with a real
  postinstall script, and asserts on the resulting `process_tree` (closes
  fork-tgid-lookup's item B as far as a single-threaded node child process
  can); a test that signals a real running monitor and reads its real exit
  code (closes silent-write-failures' item A directly).
- Goal 3 → the complete repository suite (`-race` and root, this package and
  every other) run repeatedly, not once, both before and after any fix this
  task makes.
- Goal 4 → [07-findings-not-fixed.md](07-findings-not-fixed.md) re-confirms
  each deferred item against current code, changing nothing about them.
