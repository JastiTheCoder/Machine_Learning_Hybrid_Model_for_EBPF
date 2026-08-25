# 2. Test plan — NC1

Per `skills/.agents/skills/tdd/SKILL.md`: seams confirmed before any test is
written, one vertical slice per behavior, red before green. This bug is not
timing-dependent (no goroutines race here — `verdict.Evaluate` is a pure
function), so the "reliably reproduce the vulnerable condition" bar from
`CLAUDE.md` is satisfied by a deterministic unit input, not a stress/fault-
injection harness — the false positive is 100% reproducible on the first try
given the right `Input`, which is itself part of what makes this bug severe.

## Seams to confirm with the user before writing any test

| Seam | Why this one |
|---|---|
| `verdict.RuleEXFIL001.Eval(Input)` directly | The rule's own decision function; the smallest unit that can be red before any wiring exists. Matches how every existing rule in `rules_test.go` is tested (`TestRuleCRED001`, `TestRuleRECON001`, etc.) |
| `verdict.Evaluate(Input, DefaultRules, DefaultThresholds)` | The banding step — proves the fix changes the actual `Level`, not just one rule's `fired` bool, and exercises the full default registry together (so a fix to `EXFIL-001` alone can't accidentally still reach `LevelMalicious` via some other rule combination) |
| `features.EvidenceCollector.AddPath` → `Snapshot().FirstSeen` | Where the indicator is actually marked; this is the layer Plan 1 changes directly, and the layer whose *current* over-broad behav0r must first be demonstrated red |
| `internal/output.BuildRecord` end-to-end (session → JSON `verdict` block) | Confirms the fix reaches the real output path, not just the `verdict` package in isolation — this is what an operator/`[ALERT]` line actually sees |

If the user confirms these four, no fifth seam (e.g. a full `cmd/monitor`
process-level test) is needed — Stage 9's existing root-gated end-to-end test
already covers the true-positive path at that level, and this bug does not
require kernel involvement to reproduce or fix.

## Slice 1 — reproduce the false positive at the rule level (red, on purpose, against current code)

**Test:** `TestRuleEXFIL001DoesNotFireOnNpmrcReadAloneBeforeAConnect` (or similar),
added to `internal/verdict/rules_test.go` alongside the existing `TestRuleEXFIL001`
tests.

```go
in := Input{Evidence: features.Evidence{
    FirstSeen: map[features.Indicator]uint64{
        features.IndicatorSensitiveRead:   100,
        features.IndicatorOutboundConnect: 200,
    },
}}
fired, _ := RuleEXFIL001.Eval(in)
if fired {
    t.Error("EXFIL-001 fired on an unqualified sensitive-read indicator " +
        "(e.g. an .npmrc read) before an ordinary connect; want it to require " +
        "a credential-class read specifically")
}
```

**Expected before any fix:** **red** — `fired == true`. This is the reproduction;
capture its output as evidence before touching any source, same as every prior
`docs/bugs-fixed/*/evidence/*-red.txt`.

Independently, a second test proves *where* the over-broad marking happens (not
just that the rule fires given a hand-built `Input`):

**Test:** `TestAddPathMarksSensitiveReadOnlyForCredentialClasses`, added to
`internal/features/evidence_test.go`.

```go
c := NewEvidenceCollector()
c.AddPath("/home/x/.npmrc", 0, 100)
snap := c.Snapshot()
if _, ok := snap.FirstSeen[IndicatorSensitiveRead]; ok {
    t.Error("AddPath marked IndicatorSensitiveRead for a .npmrc read; " +
        "want it restricted to credential-shaped classes")
}
```

**Expected before any fix:** **red** — the indicator is set today for every
classified path, `.npmrc` included.

## Slice 2 — the true positive must still fire (green, must already pass, kept as a guard)

Before implementing anything, add or confirm a companion test asserting the
opposite case still works, so slice 1's fix can't be satisfied by simply
disabling the rule:

**Test:** extend the existing `TestRuleEXFIL001` in `rules_test.go` (or add
`TestRuleEXFIL001StillFiresOnCredentialReadThenConnect`) with an `Input` whose
`FirstSeen[IndicatorSensitiveRead]` originates from an actual `PathClassSSHPrivateKey`
read via the real `AddPath` path (not hand-set in `FirstSeen`), to close the gap
between "the rule's own logic is right" and "the collector feeds it correctly."

```go
c := features.NewEvidenceCollector()
c.AddPath("/home/x/.ssh/id_rsa", 0, 100)
c.AddEndpoint("1.2.3.4:4444", true, 200)
in := Input{Evidence: c.Snapshot()}
fired, evidence := RuleEXFIL001.Eval(in)
if !fired {
    t.Fatal("EXFIL-001 did not fire on a genuine SSH-key read before a connect")
}
```

**Expected before any fix:** already **green** — this is the currently-correct
behavior and must stay correct. Run it once now to confirm it passes on
unmodified code (a baseline), then re-run after the fix to prove no regression.

## Slice 3 — banding: `Evaluate` no longer reaches `LevelMalicious` on this input alone

**Test:** `TestEvaluateDoesNotBandNpmrcReadThenConnectAsMalicious`, added to
`internal/verdict/verdict_test.go`, run against `DefaultRules` (the real
registry, not a hand-picked subset) and `DefaultThresholds`.

```go
c := features.NewEvidenceCollector()
c.AddPath("/home/x/.npmrc", 0, 100)
c.AddEndpoint("140.82.121.4:443", true, 200)
in := Input{Evidence: c.Snapshot()}
v := Evaluate(in, DefaultRules, DefaultThresholds)
if v.Level == LevelMalicious {
    t.Errorf("ordinary .npmrc-then-connect banded %s (score %d, findings %v); "+
        "want benign", v.Level, v.Score, v.Findings)
}
```

**Expected before any fix:** **red** — `Level == LevelMalicious`, `Findings`
contains `EXFIL-001`.

## Slice 4 — end-to-end: `BuildRecord`'s persisted `verdict` block agrees

**Test:** extend `internal/output/verdict_output_test.go` with a session built
via the real `Session`/`Snapshot()` path (mirroring
`TestBuildRecordFeatureFieldsUnaffectedByVerdict`'s existing construction
pattern) that only does an `.npmrc` read and a connect, and assert
`record.Verdict.Level != verdict.LevelMalicious`.

**Expected before any fix:** **red**, for the same underlying reason as slice 3,
proven at the layer `cmd/monitor` actually serializes.

## Regression guard: the 36 feature fields are untouched

Run `TestBuildRecordFeatureFieldsUnaffectedByVerdict` unmodified after the fix —
it must still pass. This is not a new test; it is an existing guard this bug's
fix must not break, listed here so the implementing session doesn't skip it.

## Teeth-check plan

Slices 1, 3, and 4 are, by construction, red before the fix and must turn green
after it — no separate teeth-check is needed beyond that red→green transition
itself (unlike a race, there's no risk of a coincidentally-passing test here: the
input is deterministic). The one thing worth checking for teeth once the fix
lands: temporarily revert only the `AddPath`/indicator-scoping change (keep
everything else) and confirm slice 1 and slice 3 go red again — this rules out
the fix accidentally working "by accident" via some unrelated code path (e.g. a
threshold change made at the same time).

## Goal coverage

| Goal (from `01-bug.md`'s Expected result) | Covered by |
|---|---|
| `.npmrc`-then-connect no longer reaches `LevelMalicious` | Slices 1, 3, 4 |
| Genuine credential-read-then-connect still fires `EXFIL-001` / reaches `LevelMalicious` | Slice 2 |
| 36 feature fields unaffected | `TestBuildRecordFeatureFieldsUnaffectedByVerdict` (existing, re-run) |
| Fix is real, not coincidental | Teeth-check (revert, confirm red again) |
