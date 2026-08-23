# 6. Results

## Goals vs. outcome

| # | Goal | Outcome |
|---|---|---|
| 1 | Every corpus fixture correctly labelled | **met** — 3 benign / 10 malicious, matching ground truth exactly |
| 2 | Undeclared package never guessed at | **met** — `ErrUnknownPackage`, asserted to not look benign |
| 3 | Labeler and validator cannot disagree | **met** — both resolve through `internal/dataset` |
| 4 | No label ⇒ no training row | **met** — `ToCSVRow` errors; exporter excludes the row from the CSV |
| 5 | Failures are loud | **met** — non-zero exits, per-file `EXCLUDED`/`UNLABELLED` lines, validator Rule 4 |
| 6 | Nothing else changes | **met** — `-race` and root suites green across 9 packages |

## The measurement that matters

Independently reproducible (see
[`evidence/pre-fix-heuristic-reproduction.txt`](evidence/pre-fix-heuristic-reproduction.txt)):

```
PRE-FIX RESULT: 11 benign, 2 malicious (13 total)
GROUND TRUTH:   3 benign, 10 malicious (13 total)
MISLABELLED:    8 malicious samples labelled benign
```

After the fix, the same corpus through the real labeler:

```
Dataset: 3 benign, 10 malicious (13 total)
```

And the exported training CSV:

```
=== label distribution in the exported CSV ===
      3 0
     10 1
```

Per-row, every fixture family now carries the correct label and severity:

```
benign-test-1.0.0.tgz             label=0  severity=0
ci-secret-grabber-test-1.0.0.tgz  label=1  severity=1
crypto-miner-test-1.0.0.tgz       label=1  severity=1
env-stealer-test-1.0.0.tgz        label=1  severity=1
reverse-shell-test-1.0.0.tgz      label=1  severity=1
suspicious-test-1.0.0.tgz         label=1  severity=1
```

## The failure path, which is the half that prevents recurrence

Exporting the corpus **before** labelling it:

```
EXCLUDED npm-1776938562_suspicious-test-1.0.0.tgz.json: session "npm-1776938562"
  (package "suspicious-test-1.0.0.tgz") has no label; run the labeler before exporting
Wrote 0 rows to .../before.csv.

EXCLUDED: 13 session(s) were not exported because they have no label.
Run the labeler over the sessions directory, then export again.
exit status 1
```

Before this fix, that same command wrote 13 rows, all labelled `0`, and exited
`0`. That is the precise mechanism by which 10 malicious samples would have
entered the training set as benign examples.

## Validator

```
─── Rule 4: All files have a declared ground-truth label ───
  All files have a declared ground-truth label ✓

PASS
```

## Test results

| Package | Tests added | Result |
|---|---|---|
| `internal/dataset` | 3 functions, 12 subtests | all pass |
| `cmd/dataset/labeler` | 1 function (real corpus, end to end) | pass |
| `cmd/dataset/validator` | 3 functions, 8 subtests | all pass |
| `cmd/dataset/exporter` | 2 functions (CSV on disk) | all pass |
| `internal/output` | 2 functions, 3 subtests | all pass |

Red→green per slice: **6 slices, 6 reds, 6 greens**, each red recorded in
`evidence/`.

## Whole-repository verification

```
$ go build ./...
BUILD OK

$ go test -race ./... -count=1
ok  .../cmd/dataset/exporter   1.031s
ok  .../cmd/dataset/labeler    1.027s
ok  .../cmd/dataset/validator  1.015s
ok  .../cmd/monitor            1.040s
ok  .../internal/collector     1.023s
ok  .../internal/dataset       1.023s
ok  .../internal/features      1.035s
ok  .../internal/output        1.061s
ok  .../internal/session       1.259s

$ sudo -n /usr/bin/go test ./... -count=1
   (same 9 packages, all ok)
```

`gofmt` clean on every file touched; `go vet ./...` clean.

## Diff size

| File | Change |
|---|---|
| `internal/dataset/labels.go` | new, ~85 lines incl. comments |
| `internal/dataset/labels_test.go` | new, 3 tests |
| `cmd/dataset/labeler/main.go` | `labelFor` removed; `labelDirectory` extracted; exits non-zero on failures |
| `cmd/dataset/labeler/main_test.go` | new, corpus end-to-end regression |
| `cmd/dataset/validator/main.go` | `derivedLabel` rewritten; Rule 4 added |
| `cmd/dataset/validator/main_test.go` | new, 3 tests |
| `cmd/dataset/exporter/main.go` | `exportDirectory` extracted; excludes unlabelled rows |
| `cmd/dataset/exporter/main_test.go` | new, 2 tests |
| `internal/output/json_writer.go` | `ToCSVRow` returns an error for a nil label |
| `internal/output/json_writer_test.go` | +2 tests, 1 pre-existing test updated |

No BPF, no collector, no session schema, no monitor.

## Status of the audit's Critical findings

| Finding | Status |
|---|---|
| C1 — `write_processes`/`read_processes` broken | fixed ([docs](../fix-c1-open-flags/)) |
| C2 — unlocked concurrent read in `BuildRecord` | **open** |
| C3 — session can be completed twice | **open** |
| C4 — malicious fixtures exported as benign | **fixed** (this task) |

## What this unblocks

Re-capturing the corpus and exporting a training CSV that can actually be
trusted. Any newly captured package now either has a declared label or stops the
pipeline — it cannot quietly become a benign row.
