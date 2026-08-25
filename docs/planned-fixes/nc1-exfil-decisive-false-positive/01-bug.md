# 1. Bug — NC1: `EXFIL-001` (decisive) can band an ordinary install "malicious"

Source finding: [`../../NEW_AUDIT.md`](../../NEW_AUDIT.md#nc1-exfil-001--a-decisive-rule--can-band-an-ordinary-unmodified-npm-install-malicious).

## How it came about

Introduced whole in commit `15f2b51` ("Add userspace verdict-scoring engine; fix
FileEvent.TimestampNs alignment"), the single commit that added `internal/verdict`
and `internal/features/evidence.go` to the project. Two pieces of that commit
combine to produce the bug:

1. `EvidenceCollector.AddPath` (`internal/features/evidence.go:92-104`) marks
   `IndicatorSensitiveRead` for **every** path that classifies to a non-`PathClassNone`
   `PathClass` — all thirteen values in `internal/features/pathclass.go`, including
   `PathClassNpmrc`, `PathClassGitConfig`, `PathClassShellRC`, `PathClassDotEnv`,
   `PathClassCronDir`. There is no narrowing by "is this actually credential-shaped."
2. `RuleEXFIL001` (`internal/verdict/rules.go:279-295`) is one of two `Decisive:
   true` rules — firing forces `Verdict.Level = LevelMalicious` regardless of
   total score (`verdict/verdict.go:76-84`). It fires whenever
   `Evidence.FirstSeen[IndicatorSensitiveRead]` is earlier than
   `Evidence.FirstSeen[IndicatorOutboundConnect]` — i.e., it consumes the same
   *unnarrowed* indicator from (1) directly.

The same commit's Stage 8 calibration work *did* narrow a sibling rule,
`RuleCRED001`, to a 4-member `credentialClasses` map (`SSHPrivateKey`,
`AWSCredentials`, `DockerConfig`, `KubeConfig` — `rules.go:63-68`), specifically
*because* real captures of `lodash`/`express`/`chalk`/`debug` showed `.npmrc`
reads triggering it on every single ordinary install:

> "npm itself reads `.npmrc` as part of ordinary registry-config resolution on
> every single install ... a 100% false-positive rate with zero discriminative
> power." — `rules.go:56-61`

That narrowing was applied to `RuleCRED001`'s own path-presence check
(`Evidence.Paths`), but never propagated to the `IndicatorSensitiveRead` signal
`RuleCRED001`'s sibling rule, `EXFIL-001`, depends on — `AddPath` still marks the
indicator for all thirteen classes.

**Why the calibration pass didn't catch it too:** all four `benign-real-world`
captures committed under `sessions/` (`lodash` ×7, later `chalk`/`debug`) show
`"tcp": {"state_transitions": 0, ...}` — no TCP events were recorded for them in
that environment. `IndicatorOutboundConnect` was therefore never set for any
calibration sample, so `EXFIL-001`'s ordering condition had no real
`.npmrc`-then-registry-connect sequence to evaluate against during the one phase
of the work built to catch exactly this class of false positive. The Stage 9
end-to-end regression test (`TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert`,
`cmd/monitor/e2e_regression_test.go`) does exercise `EXFIL-001` through real
kernel events, but its fixture reads `.ssh/id_rsa` (a genuine `credentialClasses`
member) — a true positive, not the false-positive shape this bug describes.

Confirmed by direct reproduction (`internal/verdict`, scratch test, not
committed): given `Evidence.FirstSeen` with only `IndicatorSensitiveRead` at
t=100 and `IndicatorOutboundConnect` at t=200 (no `Paths` entries needed —
`RuleEXFIL001.Eval` never reads `Evidence.Paths`, only `FirstSeen`),
`RuleEXFIL001.Eval` returns `fired=true`.

## Candidate fixes

### Plan 1 (recommended) — narrow `IndicatorSensitiveRead` at the source

Change `EvidenceCollector.AddPath` to mark `IndicatorSensitiveRead` only for a
credential-shaped class set — reusing or mirroring `verdict.credentialClasses`
(`SSHPrivateKey`, `AWSCredentials`, `DockerConfig`, `KubeConfig`) — while leaving
`Evidence.Paths` itself unfiltered (all thirteen classes still recorded there, for
`RuleRECON001`, `RuleCRED001`, and any future rule that wants the broader set).

- **Cost:** `internal/features` currently has no notion of "credential class"; the
  set either needs to be duplicated there (accepting two independent definitions
  that must be kept in sync) or `verdict.credentialClasses` needs to move down
  into `internal/features` so both `AddPath` and `RuleCRED001` share one
  definition. The latter is cleaner but touches the package `verdict/rules.go`
  currently owns.
- **Risk:** confirmed by grep that `EXFIL-001` is the *only* consumer of
  `FirstSeen[IndicatorSensitiveRead]` today, so narrowing it cannot silently
  change any other rule's behavior — but this must be re-confirmed at
  implementation time in case something changed since this audit.
- **Why recommended:** smallest, most direct fix; closes the bug at the exact
  place the unwarranted breadth was introduced, and mirrors the reasoning already
  accepted for `RuleCRED001`.

### Plan 2 — add a new, narrower indicator instead of narrowing the existing one

Add `IndicatorCredentialRead` (or similarly named) to `internal/features/evidence.go`,
marked only for the credential class set, and repoint `RuleEXFIL001` at it while
leaving `IndicatorSensitiveRead` broad (any classified path) for future use.

- **Cost:** more code — a new `Indicator` constant, a second `markFirstSeen` call
  site in `AddPath`, an update to `RuleEXFIL001.Eval`.
- **Benefit over Plan 1:** keeps "any sensitive path was read" as a distinct,
  still-available signal (e.g. for a future, less strict rule) rather than
  redefining what `IndicatorSensitiveRead` means. Self-documenting: a reader of
  `RuleEXFIL001` sees `IndicatorCredentialRead` and immediately knows the scope,
  without needing to trace into `AddPath` to learn it was narrowed.
- **Trade-off vs. Plan 1:** more surface area for the same outcome; only worth it
  if `IndicatorSensitiveRead`'s current (broad) meaning is expected to matter to
  some other rule soon. No such rule exists today.

### Plan 3 (considered, not recommended as the primary fix) — make `EXFIL-001` non-decisive

Change `RuleEXFIL001.Decisive` to `false` (keep `Weight: 50`). Since
`DefaultThresholds.Malicious == 60`, a lone `EXFIL-001` firing would then land at
`LevelSuspicious` (`>= 25`), not `LevelMalicious`, closing the specific
"ordinary install gets banded malicious" complaint without touching the indicator
scoping at all.

- **Why not primary:** this is not a fix to the mis-scoped signal, it is a
  mitigation of its worst symptom. `EXFIL-001`'s own doc comment states "this
  ordering has no benign explanation for an npm install script" — which this bug
  demonstrates is false for the *current* indicator definition. Leaving the
  indicator broad and merely softening the rule's own severity papers over that,
  and weakens genuine detection: a real, minimal-footprint attacker whose only
  actions are a credential read followed by a connection (no shell spawn, no temp
  write, no other rule to corroborate) would now score only `LevelSuspicious`
  instead of `LevelMalicious`, when the fixture corpus shows this exact
  standalone pattern is realistic (`ssh-reader-test` fires `EXFIL-001` +
  `CRED-001` + `PROC-001` + `DROP-001` + `NET-001` together in practice, but a
  more careful attacker need not trigger all five).
- **Possible role as a companion, defense-in-depth change:** worth noting to
  whoever implements Plan 1 or 2 as an optional addition, not a substitute.

## Expected result

- A synthetic session whose only evidence is a `.npmrc` read (or any other
  non-`credentialClasses` `PathClass`) followed by an ordinary outbound
  connection no longer reaches `verdict.LevelMalicious` — ideally it scores `0`
  and stays `LevelBenign`, matching `RuleCRED001`'s own already-accepted
  treatment of the identical `.npmrc` case.
- `ssh-reader-test`, `env-stealer-test`, `reverse-shell-test`, and
  `suspicious-test`-shaped inputs (a genuine `credentialClasses` read strictly
  before a connect) continue to fire `EXFIL-001` and reach `LevelMalicious`,
  unchanged — this is a regression bar, not just a forward-looking one.
- `TestBuildRecordFeatureFieldsUnaffectedByVerdict`
  (`internal/output/verdict_output_test.go`) still passes unmodified: the 36
  QUT-DV25 feature fields remain untouched by this fix.
- Full repository test suite (`go test ./...`, plus the root-gated/`-race`
  suites where applicable) stays green.
