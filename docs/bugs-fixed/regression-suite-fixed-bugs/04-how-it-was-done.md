# 4. How it was done

## eBPF/kernel-boundary note, up front

This task adds no BPF code and changes no kernel-side program. Every new
test requires root and a working kernel BPF stack (same
`os.Geteuid() != 0` / `npm` skip guards this project's other real-BPF tests
already use) because it runs the real, already-compiled `monitor` binary,
which itself loads real BPF programs — but the tests exercise that loading
indirectly, through the compiled artifact, not through the verifier
directly. Nothing here needed new verifier-level validation.

## Step 0 — read every existing fix before writing anything

Read all twelve `docs/bugs-fixed/*/README.md` files, plus every
`07-findings-not-fixed.md` (or the differently-named equivalent, e.g.
`fix-c1-open-flags/07-out-of-scope-blocker.md`), in full, before deciding
what to build. This is what produced the specific list in
[01-goals.md](01-goals.md) of which sub-bugs were already fixed (and by
which later task) versus which were named but deliberately left open — the
distinction the whole rest of this task depends on getting right.

## Step 1 — decide the seam, per the TDD skill, before writing a test

Settled on driving the compiled `monitor`/`labeler` binaries as real
subprocesses against real npm installs of synthetic local fixtures — the
same shape of seam `internal/features/filetop_npm_e2e_test.go` already
established for a single collector, extended here to the whole program.
Explicitly rejected: reimplementing pieces of `main()` inside the test
(would test a reimplementation, not the real binary), and using any of the
real attack-simulation fixtures in `tests/packages/` (network-dependent,
slower, and their behavioral fidelity is not what this suite needs to
prove — see [05-why-this-approach.md](05-why-this-approach.md)).

## Step 2 — build the shared harness, slice by slice

Wrote `buildMonitorBinary`, `startMonitor`, `stopMonitor` first, verified
against a trivial smoke check (monitor starts, reports active, accepts
SIGINT, exits 0) before writing any real assertion — a vertical slice
proving the harness itself works before building a test on top of it.

## Step 3 — `TestMonitorEndToEnd_PathLikeInstallIsCapturedTreeAndSanitized`, five rounds of red

Documented in full in [02-tests.md](02-tests.md): a genuine compile-time red
(helpers didn't exist yet), then four rounds of red caused by the test's own
construction, each investigated rather than assumed to be a real bug before
being fixed in the test:

1. **256-byte argv truncation** (`ProcessEvent.Args`, `process_tracer.bpf.c`)
   colliding with this project's own long test names. Confirmed by reading
   the struct's doc comment and the BPF source, not guessed.
2. **npm 12.x's `allowScripts` lifecycle-script gating** silently skipping
   the postinstall entirely. Confirmed independently, outside the test, by
   hand: `npm config list -l` showed `allow-scripts` and
   `dangerously-allow-all-scripts` config keys; `npm help install-scripts`
   documented the mechanism; a manual `npm install --foreground-scripts`
   reproduced the exact warning seen in the failing test's verbose log; a
   manual `npm install --dangerously-allow-all-scripts --foreground-scripts`
   confirmed the script then actually ran (its own `console.log` output
   appeared).
3. **A second truncation**, caused by fixing the first: adding
   `--dangerously-allow-all-scripts` to the argv pushed the install target
   itself out of the 256-byte budget. Fixed by reordering, not by further
   shortening — the target now goes immediately after `install`.
4. **Cross-test contamination under the full suite**: found only by running
   the complete repository suite, not this test alone, exactly the
   discipline the H5 fix's own `ProcessCollector` deadlock discovery already
   established as necessary in this project. Root-caused to the monitor's
   own correct, by-design behavior (it watches the whole machine for npm
   activity) colliding with another package's own concurrent real-npm-install
   test. Fixed by matching on this test's own distinctive package name
   rather than assuming exclusivity.

Each of these four was verified as a test-construction issue, not a
production regression, before being fixed as such — by reading the relevant
source (`ProcessEvent`'s doc comment, `process_tracer.bpf.c`,
`filetop_npm_e2e_test.go`'s own precedent) and, for the npm behavior
specifically, reproducing it independently outside the failing test via
manual `npm install` invocations, rather than fixing the test blind.

## Step 4 — the other two tests, built on the now-proven harness

`TestMonitorEndToEnd_BenignAndMaliciousFixturesAreLabeledCorrectly` and
`TestMonitorEndToEnd_ExitsNonZeroAndReportsLossWhenOutputCannotBeWritten`
reused every helper built in Step 3 and needed only one further correction
each (an exact-count assertion loosened in the labeling test for the same
ambient-contamination reason as Step 3's fourth red; the loss-report
assertion in the exit-code test was written pattern-based from the start,
having already learned the lesson).

## Step 5 — run the whole repository suite, not just the new tests

Per this task's own instruction and this project's established discipline:
`go build ./...`, `go vet ./...`, `go test -race ./...`, then
`sudo -n /usr/bin/go test ./...` — all packages, not just `cmd/monitor`.
This surfaced `TestRouter_UnknownPID`'s failure, documented in full in
[02-tests.md](02-tests.md): reproduced in isolation (4 of 5 standalone runs
failed, ruling out interference from this task's own new tests), root-caused
by reading `Router.Run`'s dispatch loop, fixed with the same
`waitForCondition` pattern its sibling test already used, and verified
closed with 15 consecutive clean runs plus 3 repeated `-race` runs.

## Step 6 — re-verify everything, together, repeatedly

```
$ go build ./...                                 BUILD OK
$ go vet ./...                                   clean
$ go test -race ./... -count=1                   9/9 packages ok
$ sudo -n /usr/bin/go test ./cmd/monitor/... \
    -run TestMonitorEndToEnd -v -count=1          3/3 new tests pass, isolated
$ for i in 1 2 3; do sudo -n /usr/bin/go test \
    ./... -count=1; done                          3/3 full-suite root runs, zero failures
```

Raw: [`e2e-tests-isolated-run.txt`](evidence/e2e-tests-isolated-run.txt),
[`full-root-suite-3x-clean.txt`](evidence/full-root-suite-3x-clean.txt),
[`race-suite.txt`](evidence/race-suite.txt).

## Step 7 — confirm the real binary once more

```
$ sudo -n /usr/bin/go run ./cmd/monitor -dry-run
  All probes loaded successfully.
```

Unchanged from every prior fix's own confirmation — this task touches no BPF
attachment code. Raw:
[`dry-run-confirmation.txt`](evidence/dry-run-confirmation.txt).
