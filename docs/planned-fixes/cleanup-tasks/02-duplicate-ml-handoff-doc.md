# Cleanup — duplicate `ml_handoff.md`

Source: [`../../NEW_AUDIT.md`](../../NEW_AUDIT.md) Medium finding ("`docs/
ml_handoff.md` is duplicated verbatim"). Not a code bug — no TDD test suite
applies; this is a file-organization action. Cross-referenced by
[`../h6-ml-handoff-csv-table-mismatch/`](../h6-ml-handoff-csv-table-mismatch/),
which fixes this file's *content*; sequence that bug's fix together with (or
immediately before/after) this cleanup so the two copies aren't left to
re-diverge.

## Current state (verified at audit time, 2026-08-25)

- `docs/ml_handoff.md` and `docs/misc/ml_handoff.md` are byte-identical
  (`diff docs/ml_handoff.md docs/misc/ml_handoff.md` → no output).
- `docs/ml_handoff.md` was created in commit `8ac3f5f` (2026-04-03).
  `docs/misc/ml_handoff.md` was created later, as an exact copy, by commit
  `cedca3f` ("Fix C3: session could be completed twice via exit/timeout race",
  2026-08-23) — an unrelated bug-fix commit that bundled in a docs
  reorganization it didn't need, contrary to this project's own stated
  `CLAUDE.md` convention: *"Stage only files relevant to this fix... Don't
  sweep in unrelated changes."*
- `docs/misc/` already holds `architecture_deep_dive.md`, a genuinely
  misc/reference-category doc under the taxonomy `CLAUDE.md` defines
  (`docs/bugs-fixed/`, `docs/new-features/`, `docs/misc/`); `docs/ml_handoff.md`
  sitting at the top level, outside that taxonomy, looks like the original,
  pre-taxonomy location.

## Plan

1. Pick one canonical location. Recommended: `docs/misc/ml_handoff.md`,
   consistent with `architecture_deep_dive.md` already living there and with
   `CLAUDE.md`'s own three-category convention (`docs/misc/` is explicitly for
   "anything that doesn't cleanly fit" bugs-fixed/new-features, which describes
   a standing ML-handoff reference doc well).
2. Before deleting the other copy, grep the repository for any links or
   references to the path being removed (e.g. `grep -rn "docs/ml_handoff.md"`
   across `.md`, `.go`, and script files) — `NEW_AUDIT.md` itself references
   `docs/ml_handoff.md` directly; update any such reference to point at the
   surviving canonical path.
3. Delete the non-canonical copy.
4. Apply H6's content fix (phantom `unknown_ops` row, garbled final row — see
   `../h6-ml-handoff-csv-table-mismatch/01-bug.md`) to the single surviving
   file, either as part of this same cleanup or immediately adjacent to it, so
   there is never a window where a fixed and an unfixed copy coexist.

## Verification

- `find . -iname 'ml_handoff.md'` (from the `src/npm-ebpf-monitor` root) returns
  exactly one result.
- No remaining reference in the repository (docs, scripts, or `NEW_AUDIT.md`
  itself, once updated) points at the deleted path.
- If H6's fix is applied in the same pass: H6's own consistency test (if that
  plan is chosen) passes against the single surviving file.
