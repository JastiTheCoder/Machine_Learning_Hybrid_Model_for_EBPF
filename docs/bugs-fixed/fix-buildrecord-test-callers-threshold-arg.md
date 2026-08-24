# Fix — `internal/output` test package failed to build after `BuildRecord`'s signature changed

This is a small, single-file fix, documented as one page rather than the
multi-file `fix-*/` directory used for AUDIT.md findings, because the work
is proportionate to that: a compile-breakage left behind by an unrelated
commit, not a new investigation.

## Goals

`15f2b51` ("Add userspace verdict-scoring engine; fix FileEvent.TimestampNs
alignment" — see
[`docs/new-features/001-verdict-scoring-engine`](../new-features/001-verdict-scoring-engine/README.md))
changed `BuildRecord`'s signature in `internal/output/json_writer.go`:

```go
func BuildRecord(sess *session.Session, installFeatures features.InstallFeatures, thresholds verdict.Thresholds) SessionRecord
```

It added the new `verdict.Thresholds` parameter, updated the one production
caller (`cmd/monitor/main.go:364`), and added its own new test file
(`internal/output/verdict_output_test.go`) — but never touched the
*existing* `internal/output/json_writer_test.go`, which still called the
two-argument form at four call sites. That left `go build`/`go test` for the
whole `internal/output` package failing outright:

```
internal/output/json_writer_test.go:164:30: not enough arguments in call to BuildRecord
	have (*session.Session, features.InstallFeatures)
	want (*session.Session, features.InstallFeatures, verdict.Thresholds)
```

...and three more, identical, at lines 459, 471, 614.

Goal: make `internal/output` compile and its existing tests pass again,
without changing what any of those tests actually verify.

This isn't an AUDIT.md item — `verdict`/thresholds aren't mentioned anywhere
in `AUDIT.md`, and this was surfaced while merging `fix/audit-critical-
findings` into `main` and running the full suite as a post-merge check, not
while working an audit finding. Confirmed there's no existing doc covering
it: `docs/new-features/001-verdict-scoring-engine/` documents the feature
that *caused* the gap, not this gap itself.

## Tests written out

None new. The four affected tests already existed and already specify the
behavior under test; they just couldn't compile:

- `TestBuildRecord_NilSafety` (line 164) — `BuildRecord` must not panic on a
  freshly-created, otherwise-empty session.
- `TestBuildRecordIsSafeWhileSessionIsStillBeingWrittenTo` (lines 459, 471)
  — `BuildRecord` must not race with a session's collectors writing to it
  concurrently (this is C2's regression test).
- `TestBuildRecordOnCompletedSessionWhileCollectorsStillWrite` (line 614) —
  the real `Detector` → `Completed()` → `BuildRecord` path, end to end.

None of these four tests assert anything about verdict bands or thresholds
— they predate the verdict feature entirely — so the correct fix is to pass
a threshold value and otherwise leave every assertion alone. Per TDD's rule
of testing at pre-agreed seams: the seam here (`BuildRecord`'s public
signature) didn't move in a way that changes what these tests should
observe, only in a way that changes how to call it. There's no new
red→green cycle to run — no new behavior is being specified — so the fix is
the mechanical call-site update, verified by turning "won't compile" into
"passes," not by writing a new assertion.

## How it was done

1. Confirmed the four call sites and the exact compiler error (`go test
   ./...`, see Goals above).
2. Checked what value made sense to pass at each: `verdict.DefaultThresholds`
   (`internal/verdict/verdict.go`, `Thresholds{Suspicious: 25, Malicious:
   60}`) — the same value `cmd/monitor/main.go` falls back to by default,
   and the value `internal/verdict/verdict_test.go` uses throughout for
   tests that aren't specifically exercising threshold-band edges.
3. Added `verdict.DefaultThresholds` as the third argument at all four call
   sites (lines 164, 459, 471, 614) and added the missing
   `github.com/aniruddha/npm-ebpf-monitor/internal/verdict` import.
4. Reran `go build ./...`, `go vet ./...`, `go test ./...` (unprivileged —
   the eBPF-load tests self-skip with `requires root to load BPF programs`
   rather than silently passing; confirmed via `-v` that skip messages
   actually fire), then `sudo -n /usr/bin/go test ./...` for the full suite
   including real BPF load/run.

## Why this approach

- **`verdict.DefaultThresholds`, not a locally-defined `Thresholds{}` zero
  value or a bespoke test value:** a zero-value `Thresholds{}` bands
  everything as `malicious` at score 0 (`Suspicious`/`Malicious` both 0),
  which is a real, distinct threshold policy, not "no thresholds" — using it
  here would silently make these three tests exercise a threshold band
  nobody actually configures. `DefaultThresholds` is what production uses by
  default and what the rest of the test suite already treats as the
  neutral/baseline value, so it keeps these tests' actual claims (nil
  safety, no data race) independent of verdict-banding specifics, matching
  intent.
- **Fix the test file only, not `BuildRecord` itself:** the signature change
  and its rationale live in `001-verdict-scoring-engine`'s own doc set and
  were reviewed as part of that work; reopening that design here would be
  redoing an already-settled decision, and CLAUDE.md's scope rule (don't
  touch things beyond the item at hand) applies by the same logic even
  though this isn't an AUDIT.md item.
- **No new doc-set directory (`fix-*/` with 01-07 + `evidence/`):** that
  structure exists so a reader can audit a nontrivial fix's tests, steps, and
  raw output independently. Here the entire diff is four call sites plus one
  import line, with zero behavior change; a seven-file, evidence-folder
  writeup would imply investigative weight this didn't have.

## Results

```
$ go build ./... && go vet ./...
(clean, no output)

$ go test ./...
ok  	.../cmd/dataset/exporter
ok  	.../cmd/dataset/labeler
ok  	.../cmd/dataset/validator
ok  	.../cmd/monitor
ok  	.../internal/collector
ok  	.../internal/dataset
ok  	.../internal/features
ok  	.../internal/output      0.025s   # previously: FAIL [build failed]
ok  	.../internal/session
ok  	.../internal/verdict

$ sudo -n /usr/bin/go test ./...        # full suite incl. real BPF load/run
ok  	.../cmd/dataset/exporter
ok  	.../cmd/dataset/labeler
ok  	.../cmd/dataset/validator
ok  	.../cmd/monitor            8.569s
ok  	.../internal/collector     4.873s
ok  	.../internal/dataset
ok  	.../internal/features      2.271s
ok  	.../internal/output        0.019s
ok  	.../internal/session       0.713s
ok  	.../internal/verdict
```

`internal/output` is the only package this change touches. It contains no
eBPF/kernel code — `BuildRecord` operates on already-decoded `session.Session`
data — so its own tests validate at the ordinary `go test` level, no
verifier or root/CAP_BPF needed. The `sudo -n /usr/bin/go test ./...` run
above is the full-repo confirmation (including the packages that do load
real BPF programs), run to verify the *merge* as a whole, not because this
specific fix required it.

## Findings not fixed

Fresh re-check of `AUDIT.md` against the repo as of this commit — read every
Critical/High item's current code, not just its doc's own claim, and
re-checked Medium/Low at a lighter pass:

**Fixed, each with its own `docs/bugs-fixed/` doc:** C1 (`fix-c1-open-flags`),
C2 (`fix-c2-buildrecord-race`), C3 (`fix-c3-double-completion`), C4
(`fix-c4-ground-truth-labels`), H2 (`fix-pending-opens-leak`), H3
(`fix-dead-detector-run`), H5 (`fix-collector-drop-counting`), plus
fork-tgid-lookup and ProcessTracer-load (folded into the C1/C4 commit) and
output-filename-sanitization/silent-write-failures — all backed by
`docs/bugs-fixed/regression-suite-fixed-bugs`.

**Fixed as a side effect, not separately documented:** **H1** (`d.timers`
leak on timeout). AUDIT.md filed this separately from C3, but
`internal/session/detector.go`'s timeout callback (`startSessionTimer`,
~line 419) now calls `d.stopSessionTimer(npmPID)` unconditionally before
racing for completion — the same fix that closed C3's double-completion race
also closes H1's leak, and the code comment there cites C3 explicitly. No
dedicated H1 doc exists; worth a one-line cross-reference in
`fix-c3-double-completion` at some point, but that's outside this fix's
scope.

**Partially mitigated, not resolved: H4.** `fix-route-drop-counting` gave
`RouteToSession` an atomic `DroppedRoutesForUnknownPID` counter and a log
line (verified present at `internal/session/detector.go:42-45,152-155` and
covered by `router_test.go`). But the underlying claim AUDIT.md actually
flags — that the router's channel-priority pattern doesn't guarantee
delivery ordering across five independent per-collector goroutines — is
still true of the code as written; counting/logging a drop isn't the same
as preventing one. Confirmed no ordering/sequencing change exists in
`internal/session/router.go`.

**Confirmed still open, unfixed:**
- **H6** — `docs/ml_handoff.md` still has the exact phantom-row-29 /
  garbled-final-row defect AUDIT.md describes (verified by reading the
  current file: `unknown_ops` still listed as column 29, and the final row
  is still `39–1: `p10_error_handle` then | severity_score | ...`). The code
  (`ToCSVRow`, `csvHeader`) remains internally correct; only the doc is wrong.
- **H7** — no PID generation/epoch guard exists anywhere in
  `internal/session/detector.go`; `handleExec`/`pidToSession` still key
  purely by PID number, so the cross-contamination risk on PID reuse stands
  exactly as described.
- **All Medium and Low items** (dead `writer.go`/`aggregator.go`/
  `collector.go` stubs, stale `BINARY` name in `compare_packages*.sh`,
  `make clean` targeting the wrong directory, unwired `clang-14`/
  `llvm-strip-14` pins, duplicate BPF-object loading in
  `TcpCollector`/`BytesCollector`, `InstallExtractor` discarding partial
  results on parse error, loose `isNpmInstallInvocation` substring match,
  O(N) `unregisterSession` scan, no `-race`/`test` target/CI, stray
  `test_tcp_direct.go`) — none of these are touched by any commit on
  `fix/audit-critical-findings` or by this fix; spot-checked several
  (`Makefile clean`, `scripts/compare_packages.sh`'s `BINARY` var,
  `writer.go`'s stub body) directly against current source and confirmed
  each is still exactly as AUDIT.md describes.

No AUDIT.md item concerns `BuildRecord`'s thresholds parameter or the
verdict-scoring engine itself — that's net-new functionality documented in
`docs/new-features/001-verdict-scoring-engine`, not an audit finding. This
fix is an isolated test-file compile fix with no production code change, so
it doesn't move any of the above.
