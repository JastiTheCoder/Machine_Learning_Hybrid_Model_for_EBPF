# 6. Results

## Goals vs. outcome

| # | Goal (from [01-goals.md](01-goals.md)) | Outcome |
|---|---|---|
| 1 | Rich per-event evidence reaches the scoring boundary | **met** — `internal/features/{pathclass,argvclass,evidence}_test.go`, every class covered with a near-miss negative |
| 2 | Weighted rule engine, explainable | **met** — 12 rules, every `Finding` carries ID/weight/technique/evidence text |
| 3 | Decisive signals | **met** — `EXFIL-001`/`PERSIST-001`, proven both in hand-built `Input` tests and against a real kernel event (Stage 9) |
| 4 | Weights from data, not guesses | **met, honestly partial** — 3 of 12 rules recalibrated against 4 real packages; the other 9 still rest on the 6-fixture corpus plus judgment — see below |
| 5 | Rides existing contracts | **met** — `Session.Snapshot()`'s single-lock contract unchanged; race test with demonstrated teeth (Stage 5) |
| 6 | ML contract untouched | **met** — `TestBuildRecordFeatureFieldsUnaffectedByVerdict`, byte-identical feature subtree; legacy `1.0.0` records still unmarshal |

Goal 4 in full: Stage 8 added four real, unmodified packages
(`lodash`/`express`/`chalk`/`debug`) specifically to separate "unusual for
any npm install" from "unusual for our own fixtures" — and it did exactly
that for three rules (`CRED-001`, `PROC-003`, `DROP-001`; see
[03-what-was-done.md](03-what-was-done.md)). It did not touch the other
nine rules' weights, which remain values chosen for their qualitative
ordering (decisive signals > credential/persistence reads > single weaker
indicators) rather than independently data-derived. This is the same class
of honest partial-credit `fix-pending-opens-leak/06-results.md` gives its
own Goal 2 — stated plainly rather than rounded up to "done."

## The measurement that matters

`TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert`, the
suite's first test to prove the decisive `EXFIL-001` rule against a real
kernel event rather than a hand-built `Input`. Its first run surfaced the
`FileEvent.TimestampNs` alignment bug (see [02-tests.md](02-tests.md)'s
Stage 9 narrative for the full investigation):

**Before** (the decode-level regression test that pins the root cause)

```
--- FAIL: TestFileEventBinaryReadDecodesTimestampFromRealWireBytes
    file_collector_test.go:94: TimestampNs = 0x5060708aaaaaaaa, want 0x102030405060708
        (decode did not land on the real wire offset 272)
```

**After**

```
--- PASS: TestFileEventBinaryReadDecodesTimestampFromRealWireBytes (0.00s)
--- PASS: TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert (1.71s)
```

The end-to-end test's own assertions (`verdict.level == "malicious"`,
`EXFIL-001` present, `[ALERT]`/`MALICIOUS` on stdout, exit code 0) all
passed on the very first run too — but for the wrong reason (accumulated
score, not `EXFIL-001`), which is why that first pass was not accepted as
done. See [02-tests.md](02-tests.md) for why "the level happened to come out
right" was treated as insufficient.

## Test results

| Package | Tests added this work | New file? |
|---|---|---|
| `internal/verdict` | 20 (all of them — new package) | yes |
| `internal/features` | `evidence_test.go` (7), `pathclass_test.go` (~10), `argvclass_test.go` (1), plus 2 in `tcp_aggregator_test.go` | 3 new files |
| `internal/session` | `TestAddFileExposesSensitivePathThroughSnapshot`, `TestAddTCPNonRootEndpointOnlyFromNonRootPID`, `TestSnapshotEvidenceRaceFreeUnderConcurrentWriters` | no |
| `internal/output` | `TestCurrentSchemaVersionIsBumpedForVerdict`, `TestBuildRecordAttachesBenignVerdictForEmptySession`, `TestBuildRecordAttachesMaliciousVerdictForDecisiveEvidence`, `TestBuildRecordThresholdsAreOverridable`, `TestBuildRecordFeatureFieldsUnaffectedByVerdict`, `TestSessionRecordUnmarshalsLegacyRecordWithoutVerdictKey`, `TestToCSVRowStillHas39ColumnsWithVerdictAttached` | no |
| `cmd/monitor` | `TestRunOutputWorkerAlertsOnlyForMaliciousVerdict`, `TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert` | no |
| `internal/collector` | `TestFileEventBinaryReadDecodesTimestampFromRealWireBytes`, +1 offset assertion in `TestFileEventLayoutMatchesBPFStruct` | no |
| `internal/dataset`, `cmd/dataset/labeler` | 2 small ground-truth-table updates (not new tests; see [03-what-was-done.md](03-what-was-done.md)) | no |

Red → green: every rule and every evidence class got a genuine red before
its implementation (TDD, not retrofitted assertions). One test —
`TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert` — produced
a **seam-revealing red distinct from its own design**: its written
assertions passed on the first run, but the mechanism they were meant to
prove (the decisive rule itself firing) had not actually happened, which
was only caught by checking `verdict.findings` for `EXFIL-001` specifically
rather than stopping at `verdict.level`.

## Whole-repository verification

```
$ go build ./...
BUILD OK

$ go vet ./...
VET OK

$ go test -race ./... -count=1
ok  .../cmd/dataset/exporter    1.022s
ok  .../cmd/dataset/labeler     1.018s
ok  .../cmd/dataset/validator   1.013s
ok  .../cmd/monitor             1.028s
ok  .../internal/collector      1.012s
ok  .../internal/dataset        1.014s
ok  .../internal/features       1.018s
ok  .../internal/output         1.102s
ok  .../internal/session        2.235s
ok  .../internal/verdict        1.020s

$ sudo -n /usr/bin/go test -race ./... -count=1
ok  .../cmd/dataset/exporter    1.021s
ok  .../cmd/dataset/labeler     1.016s
ok  .../cmd/dataset/validator   1.007s
ok  .../cmd/monitor             9.279s
ok  .../internal/collector      6.061s
ok  .../internal/dataset        1.014s
ok  .../internal/features       3.716s
ok  .../internal/output         1.115s
ok  .../internal/session        1.949s
ok  .../internal/verdict        1.016s
```

Ten packages, both runs, zero `--- FAIL` lines, zero unexpected skips (every
`SKIP` in the unprivileged run is a root-gated test skipping cleanly; the
root run shows every one of those same tests passing instead). `go vet
./...` clean. `gofmt -l` reports no unformatted files among any this work
touched.

Raw: [`unprivileged-build-vet.txt`](evidence/unprivileged-build-vet.txt),
[`unprivileged-race-suite.txt`](evidence/unprivileged-race-suite.txt),
[`root-suite.txt`](evidence/root-suite.txt),
[`e2e-exfil-decisive-verdict.txt`](evidence/e2e-exfil-decisive-verdict.txt),
[`file-event-timestamp-alignment-fix.txt`](evidence/file-event-timestamp-alignment-fix.txt).

## Real-binary confirmation

The end-to-end test (`TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert`)
*is* the real-binary confirmation for this work — unlike the reference doc's
dry-run-only fallback, this project's existing `cmd/monitor/e2e_regression_test.go`
harness (`startMonitor`/`stopMonitor`/`runNpmInstall`) already builds and
runs the actual compiled binary, does a real `npm install` against a real
local package, and performs a clean graceful shutdown — the same
`sudo -n kill` limitation the reference doc hit does not apply here, because
this harness's shutdown path was established (and root-gated-tested) by
earlier work in this same overall session, not newly built for this task.

```
--- PASS: TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert (1.71s)
```

stdout captured by the test includes a live `[ALERT] ... MALICIOUS ...`
line naming the offending package (`e2e-exfil-test`), confirming the
operator-facing surface (not just the written JSON) works end to end.

## Diff size

| File | Change |
|---|---|
| `bpf/file_monitor.bpf.c` | +`filename` field on `pending_open`, enter probe reads into it directly, exit probe `memcpy`s instead of `memset`s (~28 lines) |
| `internal/collector/filemonitor_x86_bpfel.{o,go}` | regenerated (this program only) |
| `internal/collector/file_collector.go` | +`Pad2 [4]uint8` field + layout comment (13 lines) |
| `internal/collector/file_collector_test.go` | +1 test, +1 offset assertion (139 lines) |
| `internal/features/{evidence,pathclass,argvclass}.go` | new, 374 lines |
| `internal/features/{evidence,pathclass,argvclass}_test.go` | new, 270 lines |
| `internal/features/tcp_aggregator.go` + test | +53 / +37 lines (non-root endpoint tracking) |
| `internal/session/session.go` | +42 lines (evidence hydration under `s.mu`) |
| `internal/session/session_test.go` | +133 lines |
| `internal/verdict/*.go` | new package, 1057 lines (incl. `rules.go`'s twelve rules) |
| `internal/verdict/*_test.go` | new package, 443 lines |
| `internal/output/json_writer.go` | +29 lines (`Verdict` field, schema bump, `BuildRecord` signature) |
| `internal/output/verdict_output_test.go` | new |
| `cmd/monitor/main.go` | +38 lines (threshold flags, alert wiring) |
| `cmd/monitor/main_test.go` | +38 lines |
| `cmd/monitor/e2e_regression_test.go` | +148 lines (new fixture + end-to-end test) |
| `internal/dataset/labels.go` | +10 lines (4 real packages) |
| `internal/dataset/labels_test.go`, `cmd/dataset/labeler/main_test.go` | +4 lines each (ground-truth table follow-on) |

No change to `bpf/{process_tracer,syscall_tracer,tcp_monitor}.bpf.c`, or the
39-column CSV export schema.

## Status of the audit's High findings

Fresh re-check against current source, not carried over from a prior doc —
full detail and evidence in [07-findings-not-fixed.md](07-findings-not-fixed.md).

| Finding | Status |
|---|---|
| H1 — `d.timers` leak | fixed (prior work, `fix-c3-double-completion`) |
| H2 — `pending_opens` leak / uncounted insert failures | fixed (prior work, `fix-pending-opens-leak`) |
| H3 — `Detector.Run()`/`Submit*` dead in production | fixed (prior work) — re-confirmed this session |
| H4 — router priority doesn't guarantee cross-channel ordering | **open** — re-confirmed this session |
| H5 — uncounted channel drops across all 5 collectors | fixed (prior work) — re-confirmed this session |
| H6 — `ml_handoff.md`'s CSV column table self-contradictory | **open** — re-confirmed this session |
| H7 — PID-reuse aliasing on `pidToSession` | **open** — re-confirmed this session |
