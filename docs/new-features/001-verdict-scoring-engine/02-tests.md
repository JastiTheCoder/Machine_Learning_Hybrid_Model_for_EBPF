# 2. Tests

## Seams under test

Recorded before any test was written (Stage 0 of the plan), plus one seam
discovered mid-work and added to the list honestly rather than folded
silently into an existing one.

| # | Seam | Kind |
|---|---|---|
| 1 | `verdict.Evaluate(Input) Verdict` — the scoring boundary | pure Go, unprivileged |
| 2 | `features.EvidenceCollector.Add*` → `Snapshot()` — the evidence boundary | pure Go, unprivileged |
| 3 | `session.Session.Snapshot()` — evidence must ride the existing coherent-snapshot contract | pure Go, unprivileged, `-race` |
| 4 | `output.BuildRecord` / the written JSON file — the persisted contract | pure Go, unprivileged |
| 5 | The compiled `./cmd/monitor` binary's stdout + written session files | root-gated, real load/run |
| 6 | `FileEvent.Filename` as decoded by `FileCollector` from a real `openat()` | root-gated, real load/run |
| 7 | `FileEvent.TimestampNs` as decoded by `binary.Read` — **added mid-work, Stage 9** | pure Go, unprivileged (decode-level); also proven under seam 5 |

Seam 7 was not anticipated in the Stage 0 plan. It surfaced only once seams 2,
5, and 6 were composed together in a real end-to-end test — see the Stage 9
narrative below for how it was found and why it was investigated rather than
worked around.

## Per-stage narrative

### Stage 1 — kernel: carry the path through `pending_open`

**Red:** `TestFileCollectorReportsFilenameFromRealOpenat` (root-gated) — a
tracked process opens a file at a known temp path; before the fix, the
decoded `FileEvent.Filename` is all-zero, because the exit probe's own
`memset` is unconditional. This was already known-red at the moment the test
was written; the point was pinning it, not discovering it.

**Green:** `struct pending_open` gains `char filename[FILENAME_LEN]`,
`memcpy`'d from the `fname` buffer the enter probe already reads for
`classify_dir`; the exit probe's `memset` is replaced with a copy from
`po->filename`. Wire format (`FileEvent`, 280 bytes) and JSON schema are
unchanged — the field already existed at offset 4, just unfilled.

### Stage 2 — `internal/verdict` core, one rule

**Red → green**, three vertical slices in `internal/verdict/verdict_test.go`:
a vector below `NET-003`'s ratio scores `benign`; a vector above it fires the
rule, scores its weight, and the `Finding` names it; boundary scores band
exactly at `suspicious`/`malicious` (asserted precisely, not approximately).
Expected values are hand-worked, never recomputed the way `Evaluate` computes
them.

### Stage 3 — registry, decisive rules, determinism

**Red → green**, `internal/verdict/verdict_test.go` +
`internal/verdict/registry_test.go`: a decisive rule alone bands `malicious`
below the malicious threshold
(`TestEvaluateDecisiveRuleAloneForcesMaliciousBelowThreshold`); non-decisive
rules summing past the threshold also band `malicious`
(`TestEvaluateNonDecisiveRulesSummingPastThresholdAreMalicious`); identical
input evaluated twice produces byte-identical `Findings` ordering
(`TestEvaluateFindingsOrderDeterministicAcrossRepeatedCalls`);
`MustRegister` panics on a duplicate rule ID.

### Stage 4 — `features.EvidenceCollector`

**Red → green**, `internal/features/{pathclass,argvclass,evidence}_test.go`:
every declared `PathClass` classifies from its real suffix, with a
table-driven near-miss negative for each (e.g. `/home/x/.ssh/known_hosts`
must **not** be `PathClassSSHPrivateKey`); 5000 duplicate opens of the same
path yield one retained entry; 100 distinct endpoints retain 32 and set
`Truncated`; `firstSeen` keeps the *earliest* timestamp across out-of-order
calls; `Snapshot()` returns a value the collector can no longer mutate
underneath a caller still holding it.

### Stage 5 — wire evidence into `Session`

**Red → green**, `internal/session/session_test.go`: a session fed a file
event for a `.ssh/id_rsa`-suffixed path exposes `PathClassSSHPrivateKey`
through `Snapshot()`; a TCP event from the session's own root PID does not
populate `NonRootEndpoints`, one from a child PID does. The concurrency test
here has teeth, not just coverage: N goroutines calling
`AddFile`/`AddProcess`/`AddTCP` against a concurrent `Snapshot()` loop,
≥1000 iterations under `-race`, verified to actually catch a lock-discipline
regression by temporarily exposing the collector directly (outside `s.mu`)
and confirming `-race` reports it before removing that exposure again.

### Stage 6 — the full rule set

**Red → green**, one slice per rule in `internal/verdict/rules_test.go`,
every rule with both a positive and a near-miss negative — a rule with only
a positive case was not accepted. `EXFIL-001` got the most scrutiny:
`TestRuleEXFIL001` forces ordering in both directions (read-then-connect
fires, connect-then-read does not) plus separate cases for either fact
occurring alone.

### Stage 7 — output surface

**Red → green**, `internal/output/{json_writer,verdict_output}_test.go`:
`TestBuildRecordFeatureFieldsUnaffectedByVerdict` marshals a pre- and
post-verdict record for the same session and diffs the 36-feature subtree
byte-for-byte; a round-trip test unmarshals a written record with its
verdict intact; a real `schema_version: "1.0.0"` corpus file with no
`verdict` key still unmarshals with `Verdict == nil`; `cmd/monitor`'s output
worker prints `[ALERT] ... MALICIOUS` for a malicious-banded record and
prints nothing for a benign/suspicious one.

### Stage 8 — recapture and calibrate

Not a single red→green slice — a data-gathering and threshold-tuning pass.
`lodash`, `express`, `chalk`, `debug` were added to
`internal/dataset/labels.go`'s ground-truth table (required: `Lookup` refuses
undeclared packages by design) and captured for real via the compiled
`monitor` binary. Three rules were recalibrated directly against that data,
each with the specific numbers written into `internal/verdict/rules.go`'s own
comments:

- **`CRED-001` drops `.npmrc`** from its credential-class set. All four real
  packages (none of which run any install-time script) triggered it solely
  on npm's own ordinary `.npmrc` config read — a 100% false-positive rate
  with zero discriminative power.
- **`PROC-003`'s `processOpsRatioBaseline`** raised from a placeholder to
  `60.0`. The four real packages show `process_ops`/`direct_dependencies`
  ratios of 3.25–14.00 (npm's own internal spawning); `benign-test` (which
  does run a postinstall) sits at 39.00; `reverse-shell-test` — the one
  fixture that deliberately spawns many child processes — is the outlier at
  123.00. The baseline sits between those two clusters, but with a single
  malicious data point this is stated plainly as a coarse cut, not a tight
  bound.
- **`DROP-001`'s writer threshold** raised from "`>0` distinct writers" to
  "`>1`". All four real packages touch a temp directory with exactly one
  writer — npm's own tarball extraction — which made the old threshold fire
  on every install regardless of maliciousness.

`internal/dataset/labels_test.go` and `cmd/dataset/labeler/main_test.go`
needed two small, directly-entailed updates once `lodash` became a declared
package: `TestLookupRejectsUndeclaredPackages`'s "still-undeclared" examples
were swapped from `lodash`/`express` (now declared) to `react`/`axios`; the
labeler's own independent ground-truth map gained a `"lodash": 0` entry to
match the corpus's 7 real `lodash` captures.

### Stage 9 — end-to-end regression, and an unplanned second bug

**Red (test design):** `TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert`
was written to close the loop across every prior stage against real kernel
events: a synthetic local package whose postinstall reads a
`.ssh/id_rsa`-suffixed path, then connects to a listener the test itself
starts on `127.0.0.1`, in that order — the exact shape `EXFIL-001` exists to
catch.

**First run — a genuine, unanticipated red.** The test failed, but not on
the assertions it was written to check (level, alert). `verdict.level` was
already `malicious` — by accumulated score, from `CRED-001` + `PROC-001` +
`DROP-001` + `NET-001` + `NET-002` — but `EXFIL-001` itself never fired. That
was not accepted as "close enough": `EXFIL-001` firing was the entire point
of this test, and a decisive rule with no seam proving it fires against real
data is not the same claim as one that does.

**Investigated, not worked around.** Rather than loosen the assertion, the
ordering was inspected directly: a temporary debug print in
`EvidenceCollector.markFirstSeen` (reverted afterward, never committed)
showed `IndicatorSensitiveRead`'s recorded timestamp as an 19-digit,
physically nonsensical value — roughly `1.5×10^19` nanoseconds — next to
`IndicatorOutboundConnect`'s correctly-scaled `~1.5×10^13`. Decoding those
bytes showed a recognizable shape: the low 32 bits were the *next* field's
own alignment gap, not the timestamp at all.

**Root cause, confirmed at the decode level, no root required.**
`bpf/file_monitor.bpf.c`'s own layout comment places `timestamp_ns` at wire
offset 272 — four bytes *after* `flags` ends at offset 268 — because the C
compiler pads the struct so a `__u64` field starts on an 8-byte boundary.
`FileCollector.Run`'s decode path (`binary.Read(bytes.NewReader(record.RawSample),
binary.LittleEndian, &evt)`) reads a struct field-by-field using each Go
field's own declared size, with **no** awareness of that C-compiler-inserted
gap — a well-known `encoding/binary` gotcha distinct from Go's own struct
layout (which *does* insert the same gap, which is exactly why the
pre-existing `TestFileEventLayoutMatchesBPFStruct` — asserting
`unsafe.Offsetof`, Go's own memory layout — passed the whole time and never
caught this). `TestFileEventBinaryReadDecodesTimestampFromRealWireBytes`
pins this precisely: a raw 280-byte buffer with the real timestamp at offset
272 and a recognizable, non-zero fill pattern in the 4-byte gap at
268–272, decoded through the exact same `binary.Read` call `Run` uses.

```
--- FAIL: TestFileEventBinaryReadDecodesTimestampFromRealWireBytes
    file_collector_test.go:94: TimestampNs = 0x5060708aaaaaaaa, want 0x102030405060708
        (decode did not land on the real wire offset 272)
```

**Green.** `FileEvent` gained an explicit `Pad2 [4]uint8` field between
`Flags` and `TimestampNs`, matching the same explicit-padding convention the
struct already used for the 2-byte gap before `Flags`. The decode-level test
went green immediately; the end-to-end test then passed on the very next
run, `EXFIL-001` firing exactly as designed. See
[03-what-was-done.md](03-what-was-done.md) for the full before/after and
[07-findings-not-fixed.md](07-findings-not-fixed.md) for why this was in
scope to fix here rather than deferred.

```
--- PASS: TestFileEventBinaryReadDecodesTimestampFromRealWireBytes (0.00s)
--- PASS: TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert (1.71s)
```

Raw: [`evidence/e2e-exfil-decisive-verdict.txt`](evidence/e2e-exfil-decisive-verdict.txt),
[`evidence/file-event-timestamp-alignment-fix.txt`](evidence/file-event-timestamp-alignment-fix.txt).

## Goal coverage

| Goal (from [01-goals.md](01-goals.md)) | Covered by |
|---|---|
| 1 — rich evidence reaches the boundary | Stage 4/5 tests |
| 2 — explainable weighted verdict | Stage 2/3/6 tests |
| 3 — decisive signals | Stage 3/6 tests, plus the Stage 9 real-kernel proof |
| 4 — data-calibrated weights | Stage 8 |
| 5 — rides the existing contracts | Stage 5's `Snapshot()` race test, Stage 7's round-trip test |
| 6 — ML contract untouched | Stage 7's byte-identical-feature-subtree test |
