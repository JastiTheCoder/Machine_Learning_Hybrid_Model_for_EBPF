# 2. Tests

Three new whole-program tests, plus one existing test fixed. Getting each of
the three new tests to a state where it was actually validating something
(rather than failing for a reason that had nothing to do with any fix under
test) took several real, worth-recording rounds of red — distinguished below
from the one red that was a genuine, pre-existing bug.

## Seams — agreed before writing any test

| Seam | Outcome |
|---|---|
| The compiled `monitor` binary's exit code, stdout/stderr, and the session JSON files it writes, driven by real npm installs | ✅ all three new tests |
| The compiled `labeler` binary, chained after a real monitor capture | ✅ `TestMonitorEndToEnd_BenignAndMaliciousFixturesAreLabeledCorrectly` |
| Any individual collector, BPF map, or detector method in isolation | not touched — already covered by the twelve fixes' own existing tests, which this task does not duplicate |
| `Router.Run`'s dispatch loop itself | not touched — the one fix this task makes is to a *test's* synchronization with that loop, not the loop |

## `TestMonitorEndToEnd_PathLikeInstallIsCapturedTreeAndSanitized`

Installs a real local package (a path spec, guaranteed to contain `/`) with
a real postinstall script, and asserts: the monitor exits 0, the written
session's filename contains no `/`, and its `process_tree` shows at least
one propagated child (evidence the postinstall's node process was correctly
attached to the session).

**Red #1 — a genuine compile-time red**, before `runNpmInstall`/`startMonitor`
etc. existed: `undefined: buildMonitorBinary` and friends. Resolved by
writing the helpers.

**Red #2 — `package_name` truncated to `"/tmp/TestMonitorEndToEnd_PathLike…"`
with the trailing directory chopped off.** Not a production bug:
`ProcessEvent.Args` is a fixed 256-byte kernel-side buffer
(`process_tracer.bpf.c`), and this project's own long, descriptive test
names — a deliberate convention, not an accident — pushed `t.TempDir()`'s
default path past that budget before the argument being tested was even
reached. Fixed in the test: a `shortTempDir` helper using a short, fixed
prefix instead of the test's own name for any path that ends up in a
monitored process's argv.

**Red #3 — `process_tree` never grew beyond `"npm(<pid>)"`.** Investigated
rather than assumed to be a real regression: verbose monitor logs showed
many real `fork` events for the npm/node process's own internal libuv
threads, but no `exec` event for the postinstall's own child at all. Traced
to `npm install`'s own lifecycle-script gating (`npm warn install-scripts …
blocked because not covered by allowScripts`, an npm 12.x feature on this
machine) silently skipping the postinstall entirely — confirmed independently
by re-running the same install by hand with `--foreground-scripts` and
observing the warning, then again with `--dangerously-allow-all-scripts` and
observing the script's own `console.log` output land. Not a bug in any fix
this suite tests: npm never even attempted the exec this test needed to
observe. Fixed in the test: `runNpmInstall` always passes
`--dangerously-allow-all-scripts`.

**Red #4 — a second truncation, after fixing Red #3.** Adding
`--dangerously-allow-all-scripts` to the argv pushed the *target path*
(originally placed last) back over the 256-byte budget on its own, this time
losing the path entirely (`parseInstallTarget` returned `""`, so the session
carried `PackageName = "unknown"`, the documented fallback in
`session.go`). Fixed in the test: the install target is now placed
immediately after `install`, before any flag, in `runNpmInstall`'s argument
order — the field the code under test actually needs first, regardless of
how many flags follow.

**Green**, once all four were resolved: pass in isolation, and pass 3
consecutive times in a row.

**Red #5 — found only when run alongside the rest of the repository's
suite**, not in isolation: `stdout does not report 1 session written; …
Wrote 2 session record(s)` and `package_name = "./localdep"` (a fixture name
belonging to a *different* package's own test,
`internal/features/filetop_npm_e2e_test.go`'s `npm install ./localdep`,
running concurrently). Not a bug: the monitor watches the whole machine for
npm activity by design, so two tests in two different packages, each
launching their own real npm install at the same time, can and did land in
the same test's `outputDir`. Fixed in the test: assertions no longer assume
"the first/only file is mine" or "exactly N files exist" — a new
`waitForSessionWithPackageName` helper polls for a session carrying this
test's own distinctive package name specifically, tolerating any number of
unrelated extra sessions alongside it.

**Green**, confirmed clean across 3 repeated isolated runs and 3 repeated
full-suite (`sudo -n go test ./...`) runs. Raw:
[`e2e-tests-isolated-run.txt`](evidence/e2e-tests-isolated-run.txt),
[`full-root-suite-3x-clean.txt`](evidence/full-root-suite-3x-clean.txt).

## `TestMonitorEndToEnd_BenignAndMaliciousFixturesAreLabeledCorrectly`

Chains real `monitor` capture and real `labeler` labeling for one benign and
one malicious synthetic fixture named after real `internal/dataset` table
entries, asserting the final on-disk `"label"` field matches an
independently-stated literal (0 or 1) — not a value derived by calling
`dataset.Lookup` from the test itself, which would just re-test the table
this test isn't about.

Inherited the same truncation/allow-scripts/ambient-contamination fixes
built while getting the first test green (`runNpmInstall`,
`waitForSessionWithPackageName`), plus one test-specific correction: the
initial version asserted an exact `len(files) == len(fixtures)`, which is
exactly as fragile to ambient concurrent npm activity as the first test's
Red #5 — fixed the same way, by polling for each fixture's own exact
`package_name` individually rather than an aggregate file count.

**Green**, first full run once the shared helpers existed, and clean across
3 repeated isolated and 3 repeated full-suite runs.

## `TestMonitorEndToEnd_ExitsNonZeroAndReportsLossWhenOutputCannotBeWritten`

Points the monitor at a permanently-blocked output directory, drives a real
npm install so a real session completes, signals the monitor with a real
`SIGINT` from within the (root, via `sudo -n go test`) test process itself,
and asserts exit code 1 and a `"LOST N of M session(s)"` report.

This closes `fix-silent-write-failures/07-findings-not-fixed.md`'s finding
A directly: at the time that fix shipped, the only path to signalling a
root-owned monitor process was a second terminal running `sudo go run`
manually, which the sudo grant available in this environment (scoped to the
`go` binary only) could not reach from an automated test. Running the whole
test as root removes that obstacle — the test process itself is root, so it
can signal a root-owned child it spawned directly.

**Green on the first real run** once the shared helpers existed — no
red specific to this test's own logic. The exact-count assertion
(`"LOST 1 of 1"`) was pre-emptively loosened to a pattern match
(`LOST [1-9]\d* of [1-9]\d* session\(s\)`) before ever running under the full
suite, having already learned from the first test's Red #5 that ambient
concurrent npm activity is a real condition this environment produces, not
a hypothetical one.

## The one real, pre-existing bug: `TestRouter_UnknownPID`

Running the *complete* repository suite (`sudo -n go test ./...`) alongside
the three new tests — not just the new tests alone — surfaced a failure in
a completely unrelated, pre-existing test: `internal/session/router_test.go`'s
`TestRouter_UnknownPID` (the H4 fix's own regression test), reporting
`DroppedRoutesForUnknownPID() = 2, want 3`.

Reproduced deterministically and independently of any concurrent load from
this task's own new tests: run 5 times in complete isolation
(`go test ./internal/session/... -run TestRouter_UnknownPID -count=1`), it
failed 4 of 5 times, unrelated to CPU contention from anything else running
on the machine. Raw:
[`router-unknownpid-flake-before-fix.txt`](evidence/router-unknownpid-flake-before-fix.txt).

**Root cause**, confirmed by reading `Router.Run`'s dispatch loop
(`router.go`): the test sends three events on three *unbuffered* channels
from three goroutines, then waits only for those three sends to return
before checking the resulting counter. An unbuffered channel's rendezvous
synchronizes the data transfer itself; it does not synchronize whatever the
*receiving* goroutine does next. Router.Run's `select` case body
(`r.detector.RouteToSession(...)`, which performs the atomic increment this
test checks) runs *after* the channel operation that unblocks the sender —
so a sender's own goroutine can resume, call `wg.Done()`, and let the test's
main goroutine proceed to check the counter, before Router.Run has actually
finished processing that event. This is not a bug in `Router` or `Detector`:
it is a missing synchronization barrier in the test, one the same file's
`TestRouter_Multiplexing` already has, via a `waitForCondition` poll, for
the identical reason — just never applied to this particular test.

**Fix**: added the same `waitForCondition` poll, waiting for
`DroppedRoutesForUnknownPID() == 3` before checking anything else.

**Green, checked for teeth**: 15 consecutive isolated runs clean
(vs. 4-of-5 failing before), plus 3 repeated `-race` runs of the whole
`internal/session` package, plus 3 repeated full-suite root runs alongside
this task's own three new tests. Raw:
[`router-unknownpid-flake-after-fix.txt`](evidence/router-unknownpid-flake-after-fix.txt).

## Goal coverage

| Goal | Covered by | Achieved |
|---|---|---|
| 1 — whole-program seam | All three new tests | yes |
| 2 — close fork-tgid-lookup item B / silent-write-failures item A | Test 1's `process_tree` assertion; Test 3 in full | yes (single-threaded case only for item B — see [07-findings-not-fixed.md](07-findings-not-fixed.md)) |
| 3 — whole suite run repeatedly, reds documented and fixed | `TestRouter_UnknownPID` flake found, documented, fixed, and re-verified across 3 further full-suite runs | yes |
| 4 — deliberately-deferred findings left alone | [07-findings-not-fixed.md](07-findings-not-fixed.md) re-confirms each, changes none | yes |
