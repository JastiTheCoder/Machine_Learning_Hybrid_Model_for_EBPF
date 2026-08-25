# 2. Test plan — H6

No runtime code changes; the risk here is purely "the doc drifts from the code
again." Per `skills/.agents/skills/tdd/`: if a test is written at all
(Plan 1), it should still go red before the fix and green after — a doc-parsing
test written *after* fixing the doc, to match the already-fixed content, would
be tautological (the anti-pattern the skill explicitly names: "the assertion
recomputes the expected value the way the code does... so it passes by
construction").

## Seams to confirm with the user before writing any test (Plan 1 only)

| Seam | Why this one |
|---|---|
| The doc file's column table, read as plain text/lines | The artifact under test; no existing parser exists for it, so this seam must be built, not reused |
| `SessionRecord.ToCSVRow`'s real header — either the existing hardcoded header slice in `cmd/dataset/exporter/main.go`'s `csvHeader`, or a newly-extracted shared constant | The independent source of truth the doc must match; per the TDD skill's anti-tautology rule, this must be the actual production header list, not a copy hand-typed into the test to match the doc |

If Plan 2 is chosen, no seams are needed — skip this file's remaining sections
and note in the implementation session's own summary that no test plan applies.

## Slice 1 — reproduce the mismatch (red, against current doc content)

**Test:** `TestMlHandoffColumnTableMatchesRealCSVHeader` (or similar), placed
alongside `cmd/dataset/exporter`'s existing tests since that package owns
`csvHeader`.

```go
docCols := parseMlHandoffColumnTable(t, "../../../docs/misc/ml_handoff.md") // or wherever Plan 1's dedup lands it
if diff := cmp.Diff(csvHeader, docCols); diff != "" {
    t.Errorf("ml_handoff.md's column table does not match the real CSV header (-want +got):\n%s", diff)
}
```

`parseMlHandoffColumnTable` is new, minimal test-support code: given the
table's fixed structure (one markdown row per column, a `|`-delimited cell
containing the column name), extract just the ordered list of 39 names. It
should be simple enough to trust by inspection — this is test-support code, not
the thing under test — but if it has any nontrivial logic (e.g. handling the
currently-garbled final rows), write *that* parsing logic against the
**current, broken** doc file first and confirm it faithfully reports the
brokenness (phantom `unknown_ops`, garbled final row) rather than silently
swallowing it.

**Expected before any doc fix:** **red** — the parsed column list includes the
phantom `unknown_ops` and/or the garbled final-row content, which cannot match
`csvHeader`'s real 39 names.

## Slice 2 — the fix makes it green

After correcting the doc's table content: re-run slice 1's test.

**Expected after the fix:** **green** — parsed doc columns exactly equal
`csvHeader`, in order.

## Slice 3 — the check has teeth (deliberately re-break, confirm red)

Per this project's own established practice of checking "boring" tests for
teeth rather than trusting them (see `docs/bugs-fixed/fix-c3-double-completion`'s
"Two guards checked for teeth" precedent): after slice 2 passes, temporarily
reintroduce one of the two original defects (e.g. re-insert the phantom
`unknown_ops` row) and confirm the test goes red again, then revert. This
proves the parser/comparison genuinely inspects the content rather than, say,
only checking row count.

## Duplicate-file interaction

If the cross-referenced cleanup task (`../cleanup-tasks/02-duplicate-ml-handoff-doc.md`)
is resolved in the same session as this bug, the test only needs to point at
the single surviving canonical path. If the duplicate is deliberately kept (a
decision for the cleanup task, not this one), extend slice 1/2 to run the same
check against both files, so neither can silently re-diverge from the CSV
header even if they're allowed to remain two separate files.

## Goal coverage

| Goal (from `01-bug.md`'s Expected result) | Covered by |
|---|---|
| Doc table has exactly 39 correct rows, no phantom/garbled rows | Slices 1, 2 |
| Consistency check is real, not tautological | Slice 3 (teeth-check) |
| Both copies (if kept) stay in sync going forward | Duplicate-file interaction note |
