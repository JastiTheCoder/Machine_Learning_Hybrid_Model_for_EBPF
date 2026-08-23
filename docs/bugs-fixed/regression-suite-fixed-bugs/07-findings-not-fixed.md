# 7. Findings not fixed

A fresh re-check, done as part of this sweep — not a copy of any prior
fix's list. Since this task changed no production code, the status of every
`AUDIT.md` finding is unchanged from the H5 fix's own re-check
(`../fix-collector-drop-counting/07-findings-not-fixed.md`); what follows
adds what this specific task's own work surfaced, plus an explicit
re-confirmation pass over every other fix's deferred items so nothing is
silently assumed still accurate.

## A. New finding — `ProcessEvent.Args`'s 256-byte cap can silently truncate a long install target

Discovered constructing this task's own tests (see
[02-tests.md](02-tests.md), Test 1's second and fourth red), not previously
named anywhere in `AUDIT.md` or any prior fix's documentation. `ProcessEvent`
(`internal/collector/process_collector.go`)'s `Args [256]byte` field is
populated from the kernel side with a fixed 256-byte cap
(`process_tracer.bpf.c`). `parseInstallTarget`
(`internal/session/detector.go`) resolves the install target as the first
non-flag token in that (possibly truncated) string. A real npm invocation
with enough flags and/or a long enough path/package-spec argument can push
the actual target past 256 bytes, at which point `parseInstallTarget`
either returns a truncated path or, if truncation lands exactly on a flag
boundary with nothing readable after it, returns `""` — silently producing
`PackageName = "unknown"` (the documented fallback in `NewSession`,
`session.go`) instead of an error or a warning.

**Severity: Low.** Deep, nested project directories or long registry
package specs with several flags are the realistic trigger; a bare
`npm install lodash` is nowhere near the budget. Not demonstrated to have
affected any session in this project's own captured corpus (`sessions/*.json`),
all of which use short bare filenames or short paths.

**Why not fixed here:** out of scope for a regression-validation task per
`CLAUDE.md`'s own scope discipline — this is a new, distinct defect, not a
sub-bug of anything this task set out to validate, and fixing it means
either widening the kernel-side buffer (more ring-buffer bytes per event,
for every event, not just install-target ones) or switching
`parseInstallTarget`'s source to a live `/proc/<pid>/cmdline` read (subject
to its own race: the process may have already moved on or exited by the
time it's read, which is exactly why `resolveCommand` does not already do
this universally). Both are real design decisions deserving their own task.

**Suggested shape, cheapest first:** log a warning when `command`'s captured
length is suspiciously close to 256 bytes, so an operator can at least tell
a session's `package_name` might be unreliable; a live `/proc/<pid>/cmdline`
read as a fallback only when the 256-byte capture appears truncated (no
trailing NUL/short read) would recover the common case without taking on
the live-read race universally.

## B. fork-tgid-lookup's item B — closed for the real single-thread case, still open for worker-thread forking

`fix-fork-tgid-lookup/07-findings-not-fixed.md`, item B, named a real gap:
that fix's own correctness was proven only via a synthetic C fixture forking
from a non-leader pthread, never through a real npm install running a real
node child process. This task's `TestMonitorEndToEnd_PathLikeInstallIsCapturedTreeAndSanitized`
closes the real-npm/real-node half of that gap directly — a real postinstall
script's node child process is now proven, through the real kernel and the
real binary, to be correctly attached to its session's `process_tree`.

**Still open:** as documented in [05-why-this-approach.md](05-why-this-approach.md),
this does not exercise the *specific* tid-vs-tgid mismatch that fix corrected,
because an ordinary `child_process` spawn forks from Node's main OS thread.
The scenario that fix's own document names as needing a dedicated
`worker_threads`-based fixture package remains undemonstrated. Not attempted
here for the same reason that fix's own document gives: constructing and
validating such a fixture is a materially larger, less certain effort than
this task's scope.

## C. Re-confirmed unchanged — every fix's own deliberately-deferred items

Re-read against the current repository state; none reference this task's
diff (a test file and one test-only fix), and none are affected by it:

- **C1** (`fix-c1-open-flags/07-out-of-scope-blocker.md`) — the ProcessTracer
  load blocker it named is fixed (by `fix-processtracer-fork-load`); no
  other item recorded there.
- **C2** (`fix-c2-buildrecord-race/07-findings-not-fixed.md`, items A–D) —
  the untestable end-to-end seam, `RouteToSession`'s lock-release contract,
  `Session`'s still-exported fields, and `loadInstallFeatures`'s unlocked
  `Cwd` read are all unchanged; none touch `Router.Run`'s dispatch loop,
  which this task's one fix left untouched (see
  [05-why-this-approach.md](05-why-this-approach.md)).
- **C3** (`fix-c3-double-completion/07-findings-not-fixed.md`, items A–C) —
  H1 remains closed as a side effect; dead `Complete()` remains unused but
  present; the synthetic-timeout-width measurement gap is unchanged.
- **C4** (`fix-c4-ground-truth-labels/07-findings-not-fixed.md`, items A–E) —
  `BuildRecord` still never sets `Session.Label`, `Category` still unexported
  to the CSV, the capture-time provenance field remains undone, fixture-name
  collisions remain possible in principle, `severity_score` still mirrors
  `label`. This task's own labeling test exercises the two-step
  capture-then-label flow exactly as designed; it does not change any of
  these.
- **fix-dead-detector-run** (items A–C) — the audit's own coverage-gap table
  row remains resolved; `context/architecture.md`'s stale `Detector.Run`
  table row remains uncorrected (out of scope, as previously decided);
  `docs/architecture_deep_dive.md` remains accurate.
- **fix-fork-tgid-lookup** (items A, B) — item A (`CLONE_THREAD` insert-side
  gap) unchanged, still deferred; item B addressed partially by this task,
  see B above.
- **fix-output-filename-sanitization** — its own findings doc records
  possible filename collisions under sanitization as harmless while
  filenames carry a per-session ID; unchanged, and this task's Test 1
  exercises exactly the scenario that fix closed (a path-like spec) without
  needing a collision to occur.
- **fix-pending-opens-leak** (items A, B) — the unreproduced D-state leak
  scenario and H5 (independently now closed by `fix-collector-drop-counting`,
  prior to this task) are both unchanged in status by this task.
- **fix-processtracer-fork-load** — its own two findings were the ones this
  task partially re-validates (B above) and fully validates via real capture
  (Finding 1, filename sanitization, exercised directly by Test 1).
- **fix-route-drop-counting** (H4, items A–D) — the underlying cross-channel
  ordering race remains intentionally unclosed; `handleFork`'s structurally
  identical silent drop remains unfixed; no test exercises `cmd/monitor`'s
  shutdown log line for this counter directly (still true — this task's
  tests read the *loss* report, not the H4 drop-count report, at the whole-
  binary level).
- **fix-collector-drop-counting** (H5, items A–D) — `ProcessCollector`'s
  missing `is_tracked()` gate remains architectural and unfixed; the other
  three items (test coverage breadth, `cmd/monitor`-level test gap for the
  H5 report line) are unchanged.
- **fix-silent-write-failures** (items A–C) — item A is the gap this task's
  Test 3 closes directly. Items B (only the write step counted, not
  `loadInstallFeatures` failures) and C (counts not persisted to a file) are
  unchanged and still open.

## D. Re-confirmed unchanged — `AUDIT.md`'s High/Medium/Low items

- **H6** (`ml_handoff.md`'s CSV table) — documentation-only, untouched.
- **H7** (PID-reuse aliasing) — unrelated to this task's diff; unchanged.
- **All Medium/Low items** (dead stubs, stale script binary name, `Makefile
  clean` wrong directory, unpinned toolchain, duplicate BPF object loads,
  `InstallExtractor` error handling, loose `isNpmInstallInvocation`
  substring match, `unregisterSession`'s linear scan, no `-race`/`test`
  Makefile target or CI, `test_tcp_direct.go`'s stray build inclusion, and
  every Low item) — re-read in full; none reference `cmd/monitor`'s test
  suite, `Router.Run`, or anything this task's diff touches.

---

## Still open, in order of what this unblocks

Unchanged in substance from the H5 fix's own ordering: **H7** (PID-reuse
aliasing) and **fix-fork-tgid-lookup's item A** (`CLONE_THREAD` insert-side
gap) remain the highest-value items directly relevant to a long,
high-throughput real capture run. This task adds one further, low-priority
item to that list: **finding A above** (`ProcessEvent.Args`'s 256-byte cap),
worth a look if a future capture run ever shows package names arriving as
`"unknown"` or visibly truncated in the wild.
