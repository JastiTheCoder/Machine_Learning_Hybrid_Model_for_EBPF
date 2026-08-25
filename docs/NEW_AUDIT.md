# npm-ebpf-monitor — Code Audit (refresh)

**Date:** 2026-08-25
**Supersedes:** `AUDIT.md` (dated 2026-08-22, last touched at commit `16164fe`). That
document is kept as-is for history; this one re-audits the repository as it stands
three days and eleven commits later, plus the working tree's current uncommitted
state. Read together with
[`ARCHITECTURE_CHANGES.md`](ARCHITECTURE_CHANGES.md), which covers the same window
from a design perspective rather than a findings perspective.

**Scope:** identical to `AUDIT.md`'s — `src/npm-ebpf-monitor` (eBPF kernel programs,
the Go collector/session/feature/verdict/output layers, `cmd/dataset/*` and
`cmd/monitor`, test fixtures, repo hygiene). Vendored third-party projects under
`tools/` remain out of scope.

**Method:** `AUDIT.md`'s own findings were re-verified item-by-item against current
source (not against its line numbers or commit labels, several of which have drifted)
and re-classified as fixed / still open / partially mitigated. The full diff since
`AUDIT.md`'s last commit (`git diff 16164fe HEAD`, 287 files, +16,439/−249) and the
current working tree (`git status`, `git diff`) were then read for anything new. The
new `internal/verdict` package — the single largest addition in this window — got a
full read, not a spot check, because a decisive rule that mis-fires is worse than an
audit that misses it. New Critical/High claims below were independently reproduced,
not inferred from the diff (see each finding's own reproduction).

I also delegated a standard diff-scoped review (`code-review` skill, effort `high`) to
a background subagent over the same working-tree diff, for a second pass over the two
files it is naturally suited to reviewing (the newly added test fixture postinstall
scripts) while this audit did the rest by hand. Its four findings are folded into
[Test fixtures](#test-fixtures) below; they are fixture-robustness issues, not
detection-pipeline bugs, so they sit at Low/Medium rather than Critical/High.

## What this system does (updated)

`npm-ebpf-monitor` still traces an `npm install` from four CO-RE eBPF programs
through per-program ring buffers, five Go collector goroutines, one router, and a
`Detector` that maintains one `Session` per npm root PID — the shape `AUDIT.md`
described is unchanged and still sound. What is new since that document:

- **File paths are no longer dropped on the floor.** `struct pending_open` now
  carries the `openat()` path itself from the enter probe to the exit probe (it used
  to carry nothing but a directory-category byte), so `FileEvent.Filename` — always
  empty before — is finally populated. This is what makes classification of
  individual paths (SSH keys, `.npmrc`, `/etc/shadow`, cron drop-ins, …) possible at
  all in userspace.
- **A new userspace layer, `internal/verdict`, scores every completed session.**
  `Session` now also accumulates an `EvidenceCollector` (`internal/features/evidence.go`,
  `pathclass.go`, `argvclass.go`) — bounded, deduplicated evidence classified from raw
  paths, spawned-process argv, and TCP endpoints — and `internal/output.BuildRecord`
  evaluates that evidence against twelve weighted rules (`internal/verdict/rules.go`),
  two of them decisive. The result is a `verdict` block in the session JSON
  (`schema_version` bumped `1.0.0` → `1.1.0`) and a live `[ALERT]` line on
  `cmd/monitor`'s stdout for anything banded malicious.
- **Ground truth grew a real-world benign cohort.** `internal/dataset/labels.go` now
  also declares `lodash`, `express`, `chalk`, `debug` — real, unmodified npm-registry
  packages — as `benign-real-world`, used to calibrate three of the twelve verdict
  rules against actual installs rather than only the project's own hand-written
  fixtures.
- Eight of `AUDIT.md`'s eleven Critical/High findings are now fixed (C1–C4, H1, H2,
  H3, H5); see [Re-verified against AUDIT.md](#re-verified-against-auditmd-not-copied).
  Two Critical findings and one High finding are new to this document.

---

## Critical

### NC1. `EXFIL-001` — a decisive rule — can band an ordinary, unmodified npm install "malicious"

`internal/verdict/rules.go`'s `RuleEXFIL001` is one of two `Decisive: true` rules: if
it fires, `Evaluate` forces `Level = LevelMalicious` regardless of total score,
overriding every threshold. It fires whenever
`Evidence.FirstSeen[IndicatorSensitiveRead]` precedes
`Evidence.FirstSeen[IndicatorOutboundConnect]` — i.e., *any* classified path read
before *any* outbound connection.

`IndicatorSensitiveRead` is set by `EvidenceCollector.AddPath`
(`internal/features/evidence.go:92-104`) for **every** non-`PathClassNone` match —
all thirteen `PathClass` values in `pathclass.go`, including `PathClassNpmrc`,
`PathClassGitConfig`, `PathClassShellRC`, and `PathClassDotEnv` — not just the four
narrow `credentialClasses` (`SSHPrivateKey`, `AWSCredentials`, `DockerConfig`,
`KubeConfig`) that `RuleCRED001` was explicitly recalibrated to use instead
(`rules.go:49-68`).

That recalibration is documented and well-reasoned for `CRED-001`:

> "npm itself reads `.npmrc` as part of ordinary registry-config resolution on every
> single install ... Live captures of four unmodified real-world packages ... all
> triggered this rule solely on their own `.npmrc` read, a 100% false-positive rate
> with zero discriminative power." — `rules.go:56-61`

`EXFIL-001` shares the same underlying `IndicatorSensitiveRead` signal `CRED-001`
was recalibrated away from, but was never given the same treatment — it consults
`FirstSeen`, not `Evidence.Paths`, and nothing filters `AddPath`'s indicator-marking
by class. Since every npm install reads `.npmrc` during registry-config resolution
and then makes at least one outbound connection to the registry, **any ordinary
install where both the file monitor and the TCP monitor successfully capture events
satisfies `EXFIL-001`'s ordering condition on `.npmrc` alone.**

**Reproduced directly**, isolating the rule from the rest of the pipeline:

```go
in := Input{Evidence: features.Evidence{
    Paths: []features.PathClass{features.PathClassNpmrc},
    FirstSeen: map[features.Indicator]uint64{
        features.IndicatorSensitiveRead:   100,
        features.IndicatorOutboundConnect: 200,
    },
}}
fired, evidence := RuleEXFIL001.Eval(in)
// fired == true
// evidence == "sensitive read at t=100 preceded outbound connect at t=200"
```

`go test -run TestScratch_EXFIL001FiresOnNpmrcThenConnect ./internal/verdict/...`
against this exact input: **PASS**, `fired=true`. (Scratch test, not committed —
see this doc's own claim standard: reproduced, not merely argued.)

**Why this was not caught by Stage 8's calibration or the Stage 9 end-to-end test:**
the four `benign-real-world` captures (`lodash`, `express`, `chalk`, `debug`)
committed under `sessions/` all show `"tcp": {"state_transitions": 0, ...}` — no TCP
events were captured for them in this environment at all (confirmed directly:
`sessions/npm-1787577634_debug.json` and six siblings). `IndicatorOutboundConnect`
was therefore never set for any calibration sample, so `EXFIL-001`'s ordering
condition had no chance to evaluate against a real `.npmrc`-then-registry-connect
sequence during calibration. The Stage 9 root-gated end-to-end test
(`TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert`,
`cmd/monitor/e2e_regression_test.go`) is real and does exercise `EXFIL-001`
end-to-end through actual kernel events — but its fixture reads a genuine credential
path, `.ssh/id_rsa`, so it proves the rule fires *correctly* on a true positive; it
does not exercise a benign `.npmrc`-then-connect sequence, so it could not have
caught this.

**Why it matters:** this is the newest, most architecturally significant addition to
the project (an explainable verdict engine is the headline deliverable of
`docs/new-features/001-verdict-scoring-engine/`), and its most severe rule — decisive,
weight 50, overrides every threshold — has a plausible unconditional false-positive
path through completely ordinary behavior once the collector that was silently
unpopulated during calibration (TCP) starts working normally in a real deployment.
A verdict engine that cries "malicious" on `npm install lodash` under real network
conditions is not merely inaccurate; it is actively worse than no verdict at all,
because `printMaliciousAlert` (`cmd/monitor/main.go:396`) puts it directly on an
operator's screen with no hedge.

**Fix direction:** `AddPath` should mark `IndicatorSensitiveRead` only for the same
narrow class set `RuleCRED001` already uses (or a dedicated, equally-narrow class set
for "credential-shaped" reads), not for every classified `PathClass` — mirroring the
exclusion that was already judged correct for `CRED-001`. A regression test capturing
`.npmrc`-then-connect (synthetically, the same way the scratch reproduction above
does) belongs in `internal/verdict/rules_test.go` alongside the existing
`TestRuleCRED001` near-miss case, and — per this task's own standard for anything
timing-dependent — the *absence* of a false positive needs to be demonstrated with
the same rigor Stage 6 already applied to demonstrating the *presence* of a true
positive.

---

### NC2. `go test ./...` currently fails, and the failure is a symptom of a real design gap, not a fluke

Running the full suite from a clean shell right now:

```
--- FAIL: TestLabelDirectoryLabelsEveryCorpusFixtureCorrectly (0.00s)
    main_test.go:116: corpus file npm-1787576926_suspicious-test.json has fixture
    "suspicious" with no expected label in this test; update expectedLabels
FAIL
FAIL    github.com/aniruddha/npm-ebpf-monitor/cmd/dataset/labeler    0.006s
```

`cmd/dataset/labeler/main_test.go`'s `corpusDir` constant
(`../../../sessions`, i.e. the repository's real, tracked `sessions/` directory) is
read directly by `copyCorpusToTemp` and compared against a fixed `expectedLabels`
map hardcoded in the test. `sessions/` is simultaneously (a) a committed regression
fixture this test depends on byte-for-byte, and (b) the default `-output-dir` every
real invocation of the compiled `monitor`/`npm-ebpf-monitor` binary writes to
(`cmd/monitor/main.go:58`). There is no separation between the two roles.

Right now, eleven session files sit in `sessions/` that are not tracked by git and
not in `expectedLabels` (`underscore`, `moment`, `chalk`, `axios`, `uuid`, `dotenv`,
`debug`, a second `suspicious-test` capture, `persistence-test`, `env-stealer-test`,
`ssh-reader-test`) — the product of someone running the real binary locally to
generate fresh captures, exactly what the tool is for. That is enough, on its own,
with zero source changes, to break this test deterministically for anyone who does
so.

**Why it matters:** CLAUDE.md's own acceptance bar for this project is "all tests
must pass." A test whose pass/fail status depends on the literal contents of a
directory the tool's normal operation writes into means the suite is not
actually deterministic against source changes alone — it can go red from running the
monitor, with no code touched, and conversely a red suite here does not reliably mean
a code regression. `AUDIT.md`'s existing Medium finding ("No `-race`, no `test`
target, no CI") already flagged that nothing runs this suite automatically; this
finding is sharper — even a developer who *does* run `go test ./...` locally, as
instructed, gets a false failure signal the moment they've also used the tool for its
intended purpose in the same checkout.

**Fix direction:** point `corpusDir` at a dedicated, version-controlled fixture
directory the test owns exclusively (e.g. `testdata/corpus/`, populated once from a
known-good capture and never touched by a live run), rather than the operational
`sessions/` directory; or exclude non-`expectedLabels` files from the loop with a
`t.Skip`/allowlist instead of `t.Fatalf`, if exercising the live corpus is
intentional. Either removes the coupling between "run the tool" and "break the
suite."

---

## High

### NH1. `Evidence.Truncated` is computed and then never surfaces anywhere

`EvidenceCollector.addCapped` (`internal/features/evidence.go:141-154`) sets
`e.truncated = true` when a session's comm or endpoint evidence hits its 32-entry
cap, and `Snapshot()` carries it into `Evidence.Truncated`
(`evidence.go:186-190`). `internal/output.BuildRecord` passes `snap.Evidence`
straight into `verdict.Input.Evidence` (`json_writer.go:173`) — but `verdict.Input`,
`verdict.Verdict`, and `verdict.Finding` (`verdict/rule.go`, `verdict/verdict.go`)
have no `Truncated` field anywhere, no rule consults it, and `SessionRecord`
(`json_writer.go:26-41`) only serializes `Verdict`, never the raw `Evidence` block
itself. **The flag is computed, threaded through two layers, and then silently
dropped before it reaches either the persisted JSON or the verdict it was meant to
qualify.**

This directly undercuts a caveat this project's own feature docs already
acknowledge:

> "`Evidence.Truncated` surfaces a cap having been hit; it does not distinguish
> [...]" — `docs/new-features/001-verdict-scoring-engine/07-findings-not-fixed.md`

That sentence is describing intended behavior that does not currently exist in the
output path — confirmed by grep: no reference to `Truncated` exists anywhere under
`internal/output` or `internal/verdict`. An operator reading a session's JSON file
today has no way to tell "this session had ≤32 endpoints and ≤32 distinct comms,
full evidence" from "this session hit the cap and evidence beyond the 32nd distinct
value was silently discarded" — for exactly the sessions (sustained, chatty,
possibly evasive installs) where that distinction matters most.

**Fix direction:** either serialize `Evidence.Truncated` (and, arguably, the rest of
`Evidence`) into `SessionRecord` directly, or add it to `Verdict` so a
`verdict.level == "malicious"` reader can also see "and evidence was truncated,
treat this score as a floor, not an exact count."

---

## Medium

- **Committed binaries doubled, not cleaned up.** `AUDIT.md`'s existing repo-hygiene
  finding ("compiled binaries are committed") is worse, not better: the repository
  now tracks **two** full compiled monitor binaries at the root —
  `monitor` (6.3 MB, tracked since before this window) and `npm-ebpf-monitor` (7.6 MB,
  currently showing as locally modified) — alongside the still-tracked `exporter`,
  `labeler`, `validator`, and `coverage.out`. The `npm-ebpf-monitor` name matches the
  Makefile's `BINARY_NAME`; `monitor` matches what `cmd/monitor/e2e_regression_test.go`
  builds on the fly via `go build -o <tmp> ./cmd/monitor`. Both names are now live in
  the repository simultaneously, with no `.gitignore` (`AUDIT.md`'s finding here is
  also still fully open — still no `.gitignore` file exists anywhere in
  `npm-ebpf-monitor`) to stop either from being re-committed.
- **`docs/ml_handoff.md` is duplicated verbatim.** `docs/misc/ml_handoff.md` and
  `docs/ml_handoff.md` are byte-identical (`diff` confirms), and both still carry
  `AUDIT.md` H6's self-contradictory CSV column table (the phantom `unknown_ops` row
  at column 29, the garbled final-row split) unfixed. Flagging rather than silently
  merging or deleting either copy, per this project's own doc-hygiene convention.
- **Working tree currently carries uncommitted capture artifacts and partially-staged
  test fixtures.** At the time of this audit: `tests/packages/env-stealer-test/` and
  `tests/packages/reverse-shell-test/` are staged but not committed; `tests/packages/
  persistence-test/` and `tests/packages/ssh-reader-test/` are new and entirely
  untracked; eleven `sessions/*.json` files are untracked (see NC2); and
  `internal/collector/syscalltracer_x86_bpfel.o`, `internal/collector/
  tcpmonitor_x86_bpfel.o`, and the `npm-ebpf-monitor` binary show as locally modified
  with no corresponding `.bpf.c` source change (confirmed:
  `git diff --stat -- bpf/syscall_tracer.bpf.c bpf/tcp_monitor.bpf.c` is empty) — i.e.
  a `go generate` or rebuild ran locally and produced non-reproducible bytecode diffs
  against source that did not change, the exact drift risk `AUDIT.md`'s existing
  Medium finding about committed `.o` artifacts already named.
- **Two new, well-designed but not-yet-wired-in test fixtures.**
  `persistence-test` and `ssh-reader-test` (see [Test fixtures](#test-fixtures)) are
  present in the working tree and independently confirmed to correctly trigger
  `PERSIST-001` and `EXFIL-001`/`CRED-001` respectively when captured — but neither
  is declared in `internal/dataset/labels.go`'s `fixtureLabels` table nor in
  `cmd/dataset/labeler/main_test.go`'s `expectedLabels`. Under the current C4-fixed
  `Lookup`, this correctly *refuses* to label them (loud, not silently wrong) rather
  than mislabeling — but it also means they cannot reach the training CSV at all
  until someone adds them, and nothing currently tracks that they're pending.
- Everything else `AUDIT.md` listed as Medium and not called out above was re-checked
  and remains open, unchanged: the dead stubs (`internal/output/writer.go`,
  `internal/features/aggregator.go`, `internal/collector/collector.go`), the stale
  binary name in `scripts/compare_packages*.sh` (still literally
  `BINARY="$PROJECT_ROOT/npm-ebpf-monitor"` — this now accidentally matches the
  binary sitting at the repo root today, by coincidence of the point above, not by
  a fix), `make clean`'s wrong target directory, the unwired pinned `clang-14`/
  `llvm-strip-14` toolchain variables, `TcpCollector`/`BytesCollector`'s double BPF
  object load, `InstallExtractor` discarding partial results on a malformed (not
  missing) lockfile, the loose `isNpmInstallInvocation` substring match,
  `unregisterSession`'s O(N) linear scan (`internal/session/detector.go:357-360`,
  unchanged), and the complete absence of a `test` Makefile target or CI
  configuration (still zero `.yml`/`.yaml` files anywhere in the repo).

---

## Low

- **Test fixtures.** {#test-fixtures}
  - `tests/packages/env-stealer-test/postinstall.js`'s outbound HTTP/HTTPS calls to
    `httpbin.org` have no timeout configured (unlike the sockets in
    `reverse-shell-test`, which call `setTimeout(4000)`); in a network-egress-filtered
    environment where SYNs are dropped rather than refused, the Node child can hang
    past the 45-second context timeout `runNpmInstall`
    (`cmd/monitor/e2e_regression_test.go`) applies to the parent `npm` process, since
    that timeout does not guarantee the orphaned child is reaped.
  - `tests/packages/reverse-shell-test/postinstall.js` drops its persistence file at
    a fixed, non-PID-suffixed path (`os.tmpdir() + '.npm-update-daemon.sh'`) and never
    cleans it up, unlike `benign-test/postinstall.js`, which unlinks its own temp
    file; concurrent runs of this fixture (e.g. a manual run overlapping CI) can race
    on the same path, and every run leaves a stray executable in `/tmp`.
  - `tests/packages/env-stealer-test/postinstall.js`'s own header comment ("no
    secrets are actually sent; connection failures are non-fatal") undersells what it
    does: it makes real, non-mocked network calls to a public third party
    (`httpbin.org`) carrying `os.hostname()` and harvested environment-variable
    *names* — consistent with `AUDIT.md`'s existing positive-note caveat about this
    pattern across several fixtures, reproduced here in a freshly re-added one, not a
    new problem but worth re-flagging since it's easy to assume "freshly written"
    means "already accounted for."
  - `tests/packages/reverse-shell-test/postinstall.js`'s recon loop uses
    `spawnSync()` inside a `try`/`catch`, but `spawnSync` does not throw on a missing
    binary (ENOENT) — it returns with `result.error` set — so a minimal environment
    missing `id`/`uname`/`whoami`/`hostname` silently logs an empty string instead of
    surfacing the real error.
  - (These four are from a diff-scoped `code-review` pass over the same working-tree
    changes; independently corroborated by direct reading of both files during this
    audit.)
- `persistence-test` and `ssh-reader-test` remain well-designed on the same standard
  `AUDIT.md` already praised: sandboxed writes under `os.mkdtempSync`, read-only
  checks against real system paths, no destructive action.
- All other `AUDIT.md` Low items (unarchitected `syscall_tracer.bpf.c` x86-64-only
  noise exclusions, dead `contains_pattern` helper, redundant nested locking,
  `NGramCounter`'s reslice churn, `tcp_aggregator.go`'s convoluted-but-correct
  byte-order helper, the `TcpEvent` alias) were re-checked and are unchanged.

---

## Re-verified against `AUDIT.md`, not copied

| ID | `AUDIT.md` finding | Status now | Evidence |
|---|---|---|---|
| C1 | `write_processes`/`read_processes` always wrong (flags never captured) | **Fixed** (already noted fixed in `AUDIT.md`'s own addendum) | `bpf/file_monitor.bpf.c:249` reads `ctx->args[2]`; `flags` field carried through `pending_open` |
| C2 | `BuildRecord` reads session state with no locking | **Fixed** | `Session.Snapshot()` (`session.go:289-330`) takes `s.mu` once; `BuildRecord` consumes only the snapshot |
| C3 | Session completed twice (timeout vs. exit race) | **Fixed** | `Session.MarkCompleteOnce` (`session.go:352-363`), a `sync.Once`-gated arbiter; both `handleExit` and the timeout callback call it and check the return |
| C4 | Malicious fixtures silently mislabeled benign | **Fixed** | `internal/dataset.Lookup` (`labels.go:71-80`) refuses undeclared packages rather than defaulting; `ToCSVRow` errors on a nil label |
| H1 | `d.timers` leaks an entry per timed-out session | **Fixed** (folded into the C3 fix) | Both completion paths call `stopSessionTimer` unconditionally before racing for the win (`detector.go:293`, `:425`) |
| H2 | `pending_opens` BPF map leaks on mid-syscall kill | **Fixed** | New `sched_process_exit` handler in `file_monitor.bpf.c:322-333` deletes the entry; insert failures counted via `file_monitor_stats` |
| H3 | Dead `Detector.Run()`/`Submit*` machinery | **Fixed** | `grep -n "detector.Run(\|\.Submit("  cmd/monitor/main.go"` — no matches; replaced by `Detector.Shutdown` |
| H4 | Router priority doesn't guarantee cross-stream ordering | **Still open** | `internal/session/router.go:51-105` — outer/inner `select` shape unchanged; `RouteToSession` now at least counts and logs the resulting drops (see H4-adjacent note below) |
| H5 | Silent event drops under backpressure, uncounted | **Fixed** | All five collectors expose `DroppedEvents()`; `cmd/monitor/main.go:192-206` reports each at shutdown |
| H6 | `ml_handoff.md` CSV table self-contradictory | **Still open**, now duplicated in two files (see Medium) | `docs/ml_handoff.md:77-91`, `docs/misc/ml_handoff.md:77-91` (identical) |
| H7 | PID-reuse aliasing, no epoch guard on `pidToSession` | **Still open** | `pidToSession map[uint32]*Session` (`detector.go:28`) unchanged; independently, the new verdict engine's own docs flag this as the leading unconfirmed explanation for a still-unresolved evidence-misattribution observation from earlier in this project's session history |

**H4 is worth one addition beyond "still open":** `RouteToSession` now counts and
(when verbose) logs every drop caused by this exact race
(`DroppedRoutesForUnknownPID`, `detector.go:127-157`) — the race itself is not
closed, but it is no longer silent, which is a real, if partial, improvement not
captured by "still open" alone.

---

## Test coverage gaps (updated)

`AUDIT.md`'s table is substantially addressed — collectors now have real test files
(`bytes_collector_test.go`, `file_collector_test.go`, `process_collector_test.go`,
`syscall_collector_test.go`, `tcp_collector_test.go`), the dead-`Detector.Run` path
noted there no longer exists to be a false coverage signal, and C2/C3's exact race
scenarios now have targeted regression tests per their own `docs/bugs-fixed/`
write-ups. What's newly true or still true:

| Area | Status |
|---|---|
| `cmd/dataset/{exporter,labeler,validator}` | Still has test files now (unlike `AUDIT.md`'s "zero test files"), but the primary one (`labeler/main_test.go`) currently fails for reasons unrelated to labeling logic — see NC2 |
| `EXFIL-001` false-positive path (non-credential `PathClass` + real connect) | **Not tested** — the exact gap behind NC1 |
| `Evidence.Truncated` reaching the output surface | **Not tested** — consistent with it not existing (NH1) |
| Cross-channel out-of-order event delivery (H4) | Still not tested |
| PID reuse / stale session aliasing (H7) | Still not tested |
| `-race` enforcement | Still no Makefile/CI target runs it, though individual `docs/bugs-fixed/*/evidence/race-suite.txt` and `docs/new-features/001-verdict-scoring-engine/evidence/unprivileged-race-suite.txt` show it was run ad hoc during development |
| `internal/output/writer.go`, `internal/features/aggregator.go`, `internal/collector/collector.go` | Still untested, still dead |

---

## Repo hygiene (updated)

- **Worse on binaries, not better.** See the Medium item above — two full compiled
  monitor binaries now tracked simultaneously, still no `.gitignore`.
- **`docs/` gained a large, well-organized `evidence/` convention** for every fix and
  the new feature (raw command output backing every claim in the corresponding
  `docs/bugs-fixed/*/` and `docs/new-features/*/` directories) — this is good
  practice for auditability, but it is also a meaningful and growing amount of
  committed plain-text log output (dozens of files, some multi-hundred-line test
  transcripts) with no stated retention policy.
- **`sessions/` still doubles as both a committed regression fixture and the tool's
  live default output directory**, with no guardrail preventing the latter from
  polluting the former (root cause of NC2).
- `coverage.out` is still tracked and still stale (unchanged from `AUDIT.md`'s
  finding).
- No CI configuration exists anywhere in the repository (unchanged).

---

## Positive notes

- The core architectural shape is unchanged and still sound, and the new
  `internal/verdict` layer is a clean, well-isolated addition to it: `verdict` only
  imports `features`, never `session`, keeping the dependency graph acyclic exactly
  as its own doc comment states (`verdict/rule.go:14-21`), and `Evaluate` is a pure
  function of its `Input` — independently testable without a `Session`,
  a collector, or root.
- The decisive-rule design itself (a rule that can override the weighted score
  entirely) is a defensible idea for genuinely unambiguous techniques
  (`PERSIST-001` — writing into a cron/systemd/shell-rc-shaped location has no
  benign npm-install explanation — is a good example and, unlike `EXFIL-001`, was
  not found to have a plausible false-positive path in this audit). NC1 is a
  calibration gap in one rule's *input signal*, not a flaw in the decisive-rule
  mechanism itself.
- `Session.Snapshot()` (C2's fix) and `MarkCompleteOnce` (C3's fix) are exactly the
  kind of single-source-of-truth primitives that make the newer `EvidenceCollector`
  wiring safe by construction: `AddPath`/`AddProcess`/`AddTCP` all mutate evidence
  under the same `s.mu` every other aggregator already uses, and `Snapshot()` clones
  it the same way — the new code did not have to reinvent synchronization discipline
  because C2 already established the pattern to extend.
- `internal/dataset`'s `fixtureLabels` table (C4's fix) made adding `lodash`/
  `express`/`chalk`/`debug` as real-world ground truth a one-line, self-documenting
  change, and its "refuse rather than guess" behavior is exactly what caught
  `persistence-test`/`ssh-reader-test` as pending-but-undeclared (see Medium) instead
  of silently mislabeling them.
- No hardcoded secrets, tokens, or user-specific absolute paths were found anywhere
  in the Go source, shell scripts, or the new `internal/verdict` package.

---

## Summary table

| Severity | Finding | Location |
|---|---|---|
| Critical (new) | `EXFIL-001` (decisive) can fire on an ordinary install's own `.npmrc` read + registry connect | `internal/verdict/rules.go` (`RuleEXFIL001`), `internal/features/evidence.go` (`AddPath`) |
| Critical (new) | `go test ./...` currently fails; root cause is `sessions/` serving two incompatible roles | `cmd/dataset/labeler/main_test.go` |
| High (new) | `Evidence.Truncated` computed, never surfaced in output or verdict | `internal/features/evidence.go`, `internal/output/json_writer.go`, `internal/verdict/*.go` |
| High | Router priority doesn't guarantee cross-stream ordering (H4) | `internal/session/router.go` — still open, drops now counted |
| High | `ml_handoff.md` CSV table self-contradictory (H6) | `docs/ml_handoff.md`, `docs/misc/ml_handoff.md` — still open, now duplicated |
| High | PID-reuse aliasing on `pidToSession` (H7) | `internal/session/detector.go` — still open |
| Medium | Two full compiled binaries now committed, still no `.gitignore` | repo root |
| Medium | `docs/ml_handoff.md` duplicated verbatim | `docs/ml_handoff.md`, `docs/misc/ml_handoff.md` |
| Medium | Uncommitted capture artifacts / non-reproducible `.o` drift in working tree | `sessions/*.json`, `internal/collector/*.o` |
| Medium | Two new fixtures not yet in ground-truth or test tables | `persistence-test`, `ssh-reader-test` |
| Medium | Carried forward unchanged from `AUDIT.md` (dead stubs, stale script binary name, `make clean`, unwired toolchain pins, double BPF-object load, `InstallExtractor` partial-result loss, loose `isNpmInstallInvocation`, `unregisterSession` linear scan, no `-race`/CI) | see [Medium](#medium) |
| Low | Test-fixture robustness (4 findings via delegated review) + carried-forward `AUDIT.md` Low items | see [Low](#low) |
