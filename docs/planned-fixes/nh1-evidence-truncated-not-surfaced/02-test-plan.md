# 2. Test plan — NH1

No concurrency or timing is involved (this is pure data plumbing), so the bar is
a deterministic red→green per layer, per `skills/.agents/skills/tdd/`'s
vertical-slice rule: one seam, one test, one minimal implementation per cycle.

## Seams to confirm with the user before writing any test

| Seam | Why this one |
|---|---|
| `features.EvidenceCollector` → `Snapshot().Truncated` | Already correct; establishes the true baseline this bug's fix must not disturb, and is the input every later slice depends on |
| `verdict.Evaluate(Input, ...)` → `Verdict` (Plan 1) or `output.BuildRecord` → `SessionRecord.Evidence` (Plan 2) | Where the fix actually lands; the layer whose current silence is this bug |
| The persisted JSON itself (`JSONWriter.Write` → file on disk) | The real observable an operator/the ML pipeline sees — a passing unit test one layer up is not sufficient proof the value reaches disk |

## Slice 0 — confirm the baseline (not a new test; a read, or a one-line assertion)

Before writing anything new, confirm `EvidenceCollector`'s existing behavior is
already correct and already tested: `evidence_test.go` should already cover
`addCapped` hitting its cap and setting `truncated`. If it does not, add
`TestSnapshotTruncatedTrueWhenCommsCapHit` first (33 distinct `AddProcess` comm
calls, assert `Snapshot().Truncated == true`) as slice 0 — this is the one
place in this plan a genuinely new *lower-layer* test might be needed, and it
should be written and confirmed green against **current, unmodified** code
before any fix-layer test is written, since it is not part of the bug.

## Slice 1 — reproduce the silence (red, against current code)

**Test (Plan 1):** `TestEvaluateSurfacesTruncatedFlag`, added to
`internal/verdict/verdict_test.go`.

```go
in := Input{Evidence: features.Evidence{Truncated: true}}
v := Evaluate(in, DefaultRules, DefaultThresholds)
if !v.Truncated {
    t.Error("Evaluate did not surface Evidence.Truncated on the returned Verdict")
}
```

**Test (Plan 2, if chosen instead):** `TestBuildRecordSurfacesEvidenceTruncated`,
added to `internal/output/verdict_output_test.go`, constructing a `Session` via
the same pattern `TestBuildRecordFeatureFieldsUnaffectedByVerdict` already uses,
feeding it enough distinct comms/endpoints to hit the cap, and asserting
`record.Evidence.Truncated == true` (or equivalent, per the exact field Plan 2
lands on).

**Expected before any fix:** **red** in either case — `v.Truncated` does not
exist yet (compile error, since the field doesn't exist under Plan 1) or
`record.Evidence` is absent (Plan 2). A compile-error red is still red per the
TDD skill's "red before green" rule — it's the natural first failure for adding
a new field a test already references.

## Slice 2 — the false case (must not default to `true`, must not be a shared global)

**Test:** a second case in the same test function (or a sibling test),
asserting a session that never hit any cap reports `false`:

```go
in := Input{Evidence: features.Evidence{Truncated: false}}
v := Evaluate(in, DefaultRules, DefaultThresholds)
if v.Truncated {
    t.Error("Evaluate reported Truncated=true for evidence that was not truncated")
}
```

This guards against a naive fix that hardcodes `true` (would pass slice 1 alone)
or leaks state across calls (e.g. a package-level variable instead of a
per-call field) — the vertical-slice discipline the TDD skill requires: this
slice exists because slice 1 alone can't distinguish "wired correctly" from
"hardcoded."

## Slice 3 — end-to-end: the persisted JSON file carries it

**Test:** extend `internal/output/verdict_output_test.go` (or add a new test
alongside it) to write a record via `JSONWriter.Write` and re-read the file,
asserting the truncation field round-trips through actual `encoding/json`
marshal/unmarshal — not just that the in-memory struct has the field set, since
a missing or wrong `json:` tag would pass slices 1-2 but silently fail to
appear on disk.

```go
path, err := writer.Write(record)
// ...
data, _ := os.ReadFile(path)
var onDisk map[string]any
json.Unmarshal(data, &onDisk)
verdictBlock := onDisk["verdict"].(map[string]any) // Plan 1
if truncated, ok := verdictBlock["truncated"]; !ok || truncated != true {
    t.Errorf("truncated flag missing or wrong in persisted JSON: %v", verdictBlock)
}
```

**Expected before any fix:** **red** (field absent from the marshaled JSON,
same root cause as slice 1, proven at the real serialization boundary).

## Regression guard

Run `TestBuildRecordFeatureFieldsUnaffectedByVerdict` unmodified after the fix —
it must still pass regardless of which plan is chosen.

## Teeth-check plan

No timing/race component. The red→green transition across slices 1 and 3 *is*
the reproduction and the fix-confirmation; no additional fault injection is
needed. One useful sanity check: after implementing, temporarily revert just the
new field/assignment (not the whole commit) and confirm slices 1 and 3 go red
again, ruling out the tests passing for an unrelated reason.

## Goal coverage

| Goal (from `01-bug.md`'s Expected result) | Covered by |
|---|---|
| Truncated session shows the flag `true` in persisted JSON | Slices 1, 3 |
| Non-truncated session shows `false` | Slice 2 |
| 36 feature fields unaffected | `TestBuildRecordFeatureFieldsUnaffectedByVerdict` (existing, re-run) |
