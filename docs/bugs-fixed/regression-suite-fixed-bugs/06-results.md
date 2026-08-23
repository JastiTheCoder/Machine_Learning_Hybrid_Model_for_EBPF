# 6. Results

## Goals vs. outcome

| # | Goal | Outcome |
|---|---|---|
| 1 | Whole-program seam, not another unit seam | **met** — `cmd/monitor/e2e_regression_test.go`, three tests, real compiled binaries |
| 2 | Close the two named verification gaps where possible | **met, partially for one** — silent-write-failures' item A fully closed; fork-tgid-lookup's item B closed for the real-npm/real-node case, not the worker-thread case (see [05-why-this-approach.md](05-why-this-approach.md)) |
| 3 | Run the whole suite repeatedly; document and fix any red | **met** — `TestRouter_UnknownPID`'s flake found, root-caused, fixed, and re-verified |
| 4 | Deliberately-deferred findings left alone | **met** — [07-findings-not-fixed.md](07-findings-not-fixed.md) re-confirms each |

## What the new tests prove that no existing test did

Before this task, no test in the repository started the real `monitor`
binary, drove a real npm install through it, and inspected the real session
JSON it wrote. After:

```
=== RUN   TestMonitorEndToEnd_PathLikeInstallIsCapturedTreeAndSanitized
--- PASS: TestMonitorEndToEnd_PathLikeInstallIsCapturedTreeAndSanitized (1.70s)
=== RUN   TestMonitorEndToEnd_BenignAndMaliciousFixturesAreLabeledCorrectly
--- PASS: TestMonitorEndToEnd_BenignAndMaliciousFixturesAreLabeledCorrectly (2.62s)
=== RUN   TestMonitorEndToEnd_ExitsNonZeroAndReportsLossWhenOutputCannotBeWritten
--- PASS: TestMonitorEndToEnd_ExitsNonZeroAndReportsLossWhenOutputCannotBeWritten (2.81s)
```

Each pass is now direct evidence, through the real binary, of: C1's file-open
flags reaching a real session; processtracer-fork-load's kernel load fix
holding on this machine; fork-tgid-lookup's real-npm/real-node propagation;
output-filename-sanitization surviving a real path-spec install;
C4's ground truth surviving real capture-then-label; H3's `Detector.Shutdown`
wiring (a broken wiring would have failed every test here via
`stopMonitor`'s 20s deadline, not just hung silently); and
silent-write-failures' exit-status reporting, now verified against a real
signal for the first time. Raw:
[`e2e-tests-isolated-run.txt`](evidence/e2e-tests-isolated-run.txt).

## The flake: before and after

Before, 5 standalone runs of the pre-existing `TestRouter_UnknownPID`:

```
ok    (run 1)
FAIL  (run 2)
FAIL  (run 3)
FAIL  (run 4)
FAIL  (run 5)
```

After, 15 standalone runs:

```
ok ok ok ok ok ok ok ok ok ok ok ok ok ok ok
```

Raw:
[`router-unknownpid-flake-before-fix.txt`](evidence/router-unknownpid-flake-before-fix.txt),
[`router-unknownpid-flake-after-fix.txt`](evidence/router-unknownpid-flake-after-fix.txt).

## Whole-repository verification

```
$ go build ./...                                BUILD OK
$ go vet ./...                                  clean
$ go test -race ./... -count=1                  9/9 packages ok
$ sudo -n /usr/bin/go test ./... -count=1       9/9 packages ok    (x3 repeated runs)
```

Raw: [`race-suite.txt`](evidence/race-suite.txt),
[`full-root-suite-3x-clean.txt`](evidence/full-root-suite-3x-clean.txt).

## Real-binary confirmation

```
$ sudo -n /usr/bin/go run ./cmd/monitor -dry-run
  All probes loaded successfully.
```

Raw: [`dry-run-confirmation.txt`](evidence/dry-run-confirmation.txt).

## Diff size

| File | Change |
|---|---|
| `cmd/monitor/e2e_regression_test.go` | new, ~440 lines: shared harness + 3 tests |
| `internal/session/router_test.go` | +14 lines: one `waitForCondition` poll added to `TestRouter_UnknownPID` |

No production code changed anywhere in the repository.

## Status of `AUDIT.md`'s tracked findings

Unchanged by this task, since no production code changed — see
[07-findings-not-fixed.md](07-findings-not-fixed.md) for the fresh
re-check. All of C1–C4, H1–H5 remain fixed; H6 and H7 remain open, as they
were before this task began.
