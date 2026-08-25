# 1. Bug — NH1: `Evidence.Truncated` is computed and then never surfaced

Source finding: [`../../NEW_AUDIT.md`](../../NEW_AUDIT.md#nh1-evidencetruncated-is-computed-and-then-never-surfaces-anywhere).

## How it came about

Introduced in commit `15f2b51` ("Add userspace verdict-scoring engine; fix
FileEvent.TimestampNs alignment") — the same commit that added the whole
evidence/verdict feature. `EvidenceCollector.addCapped`
(`internal/features/evidence.go:141-154`) has computed a `truncated` flag since
the collector was first written, set when either the `comms` or `endpoints` sets
hit their 32-entry cap (`evidenceCap`, `evidence.go:29`); `Snapshot()`
(`evidence.go:186-227`) carries it into the returned `Evidence.Truncated` field.

The gap is that nothing downstream of `Snapshot()` ever reads it again:

- `verdict.Input` (`internal/verdict/rule.go:22-31`) embeds the whole
  `features.Evidence` value (`Evidence features.Evidence`), so `Truncated` is
  *available* at rule-evaluation time — but no rule in
  `internal/verdict/rules.go` reads it, and `verdict.Verdict`
  (`internal/verdict/verdict.go:43-48`) has no `Truncated` field of its own to
  carry it forward.
- `internal/output.BuildRecord` (`internal/output/json_writer.go:166-177`) builds
  `verdict.Input{..., Evidence: snap.Evidence, ...}` — so the value is threaded
  this far — but `output.SessionRecord`
  (`json_writer.go:26-41`) only serializes `Verdict *verdict.Verdict`; it never
  serializes `Evidence` itself.

Confirmed by grep at audit time: no reference to `Truncated` exists anywhere
under `internal/output` or `internal/verdict`. The value is computed, threaded
through two full layers, and dropped immediately before the one place it would
become observable.

This appears to be an incomplete stage, not a deliberate omission: the feature's
own `docs/new-features/001-verdict-scoring-engine/04-how-it-was-done.md`
describes nine stages, the seventh of which ("output surface") added
`SessionRecord.Verdict` and the schema bump — but not this field — while a
different part of the same doc set,
`docs/new-features/001-verdict-scoring-engine/07-findings-not-fixed.md`,
describes the behavior as though it already exists:

> "`Evidence.Truncated` surfaces a cap having been hit; it does not distinguish
> [...]"

That sentence describes intended, not actual, behavior as of the commit that
wrote it.

## Candidate fixes

### Plan 1 (recommended) — add `Truncated` to `verdict.Verdict`

Add `Truncated bool` to `verdict.Verdict` (`verdict.go:43-48`), set either inside
`Evaluate` (reading `input.Evidence.Truncated` directly, alongside computing
`Score`/`Level`) or by `BuildRecord` immediately after calling `Evaluate`. No new
top-level `SessionRecord` field is needed — `Verdict` is already serialized —
and no schema-version bump is required, since this is an additive field inside
an already-additive block (schema stays `1.1.0`; a `1.1.0` reader ignoring an
unknown nested key still works, same guarantee the original `verdict` block
addition already relies on).

- **Cost:** small — one struct field, one assignment, one JSON tag.
- **Why recommended:** keeps the flag directly attached to the decision it
  qualifies ("this malicious/suspicious verdict was computed from evidence that
  may be undercounted"), which is the most useful place for an operator or the
  ML pipeline to find it, and matches the narrowest reading of what
  `07-findings-not-fixed.md` already claims exists.

### Plan 2 — serialize the full `Evidence` block onto `SessionRecord`

Add `Evidence *features.Evidence` (or a purpose-built subset) as a new field on
`output.SessionRecord`, bumping `CurrentSchemaVersion` from `1.1.0` to `1.2.0`
(additive, same backward-compatibility guarantee as the `1.0.0` → `1.1.0`
bump — see `json_writer.go:18-23`'s existing comment on why that guarantee
holds).

- **Cost:** larger — a new top-level field, a schema-version bump, and a new
  instance of `TestBuildRecordFeatureFieldsUnaffectedByVerdict`-style proof that
  the 36 QUT-DV25 fields remain untouched (a second such proof, since this is a
  second additive change after the original verdict-block addition).
- **Benefit over Plan 1:** exposes not just the truncation bit but the entire
  raw evidence set (`Paths`, `PersistenceWrites`, `Argv`, `Comms`, `Endpoints`,
  `NonRootEndpoints`, `FirstSeen`) an operator or the ML team could use for
  debugging a verdict or building richer downstream features later — valuable,
  but broader than what NH1 itself asks for.
- **Trade-off:** two schema bumps in quick succession is more churn for
  downstream consumers to track; worth doing only if there's an active reason to
  want full evidence visibility beyond the truncation flag specifically.

## Expected result

- A session whose evidence collection hits the 32-entry cap on `comms` or
  `endpoints` (constructible directly via `EvidenceCollector`, adding 33+
  distinct comms or endpoints) shows the truncation fact in the persisted JSON —
  `verdict.truncated == true` under Plan 1, or `evidence.truncated == true`
  under Plan 2.
- A session that never hits either cap shows `false` in the same field.
- `TestBuildRecordFeatureFieldsUnaffectedByVerdict` still passes unmodified: the
  36 QUT-DV25 feature fields remain untouched by this fix, regardless of which
  plan is chosen.
- Full repository test suite stays green.
