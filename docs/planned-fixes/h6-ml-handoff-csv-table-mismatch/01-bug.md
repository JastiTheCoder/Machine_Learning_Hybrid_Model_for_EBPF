# 1. Bug — H6: `ml_handoff.md`'s CSV column table is self-contradictory (and duplicated)

Source finding: `AUDIT.md` H6, re-verified still open (and now duplicated) in
[`../../NEW_AUDIT.md`](../../NEW_AUDIT.md#re-verified-against-auditmd-not-copied).
See also [`../cleanup-tasks/02-duplicate-ml-handoff-doc.md`](../cleanup-tasks/02-duplicate-ml-handoff-doc.md)
for the duplication itself as a separate, cross-referenced cleanup item.

## How it came about

`docs/ml_handoff.md` was created in commit `8ac3f5f` ("feat: add CSV export
utility and ML handoff docs", 2026-04-03) — the same commit that added the CSV
exporter itself — with the column table already self-contradictory: it inserts
a phantom row 29, `unknown_ops`, that does not exist in the real CSV (the real
`ToCSVRow`/`csvHeader` deliberately exclude `unknown_ops` from the syscalls
group, per `internal/output/json_writer.go:104-110`'s six-field syscalls block
and `cmd/dataset/validator/main.go`'s own comment, *"Syscalls (6 of the 7 —
unknown_ops excluded from QUT-DV25)"*), and garbles its own final row into an
invalid merged line, `| 39–1: \`p10_error_handle\` then | severity_score |
derived (mirrors label) |`. The doc's own inline note at line 89 already
half-acknowledges the contradiction (*"Column 39 is `p10_error_handle` and
column 40 is `severity_score`?"*) without resolving it. The code has been
internally consistent throughout — `ToCSVRow` and `csvHeader` agree with each
other exactly, and neither has ever needed a fix here; this is purely a
documentation defect, present since the doc's first commit.

A byte-identical duplicate, `docs/misc/ml_handoff.md`, was created later by
commit `cedca3f` ("Fix C3: session could be completed twice via exit/timeout
race", 2026-08-23) — an unrelated bug-fix commit that bundled in a docs
reorganization it didn't need, contrary to this project's own stated
`CLAUDE.md` convention ("Stage only files relevant to this fix... Don't sweep in
unrelated changes"). Both copies currently carry the identical, unfixed table.

## Candidate fixes

### Plan 1 (recommended) — fix the content, add an automated consistency check

Correct the column table directly: delete the phantom `unknown_ops` row 29 (and
renumber the syscalls-group rows and everything after it to match the real
6-field group), and fix the garbled final two rows so row 38 is
`p10_error_handle` and row 39 is `severity_score`, each on its own line. Do
this in whichever file is kept as canonical (see the cross-referenced cleanup
task for resolving the duplication itself) — fixing only one copy while the
duplicate still exists would immediately re-create a mismatch, so this bug's
fix and the duplicate-doc cleanup should be sequenced together, not
independently.

Additionally, add a small automated check that can't silently drift again: a Go
test (a natural home is alongside the existing `cmd/dataset/exporter` tests,
since that's the package whose `csvHeader` is the source of truth) that parses
the markdown table's column-name column out of the doc file and asserts it
matches `SessionRecord.ToCSVRow`'s real 39-column header order and names,
byte-for-byte.

- **Cost:** a small doc-parsing test — markdown tables aren't a format Go has a
  built-in parser for, so this needs either a minimal line-based parser
  (feasible given the table's simple, fixed structure) or a stricter approach:
  store the canonical 39 column names as a shared constant both the doc
  generation/verification test and `cmd/dataset/exporter` reference, and assert
  the doc file's table cells match that constant list in order.
- **Why recommended:** turns a documentation-only fix into one with a real
  regression guard — exactly the drift this bug itself is an instance of.

### Plan 2 — fix content only, no automated check

Same content fix as Plan 1, but no test — treat this purely as a prose edit,
since a markdown table isn't naturally unit-testable and the project has no
existing precedent for doc-content tests.

- **Cost:** minimal — smallest possible diff.
- **Trade-off:** re-opens the exact drift risk this bug is a case of; nothing
  would catch the table diverging from `ToCSVRow` again if either changes in
  the future.
- **When this might be the right call:** if the implementing session judges a
  doc-parsing test not worth the maintenance burden relative to the doc's low
  change frequency — a legitimate call, but should be an explicit decision
  during implementation, not a default.

## Expected result

- The doc's table has exactly 39 rows, in the same order and with the same
  names as `SessionRecord.ToCSVRow`'s real output (`package_name`, `label`, the
  5 filetop fields, 3 install fields, 7 opensnoop fields, 5 tcp fields, 6
  syscall fields — no `unknown_ops` — 10 pattern fields, `severity_score`), with
  no phantom row and no garbled merged row.
- Only one canonical copy of the file remains (or, if both are intentionally
  kept per the cross-referenced cleanup task's own decision, both are fixed
  identically and the automated check, if added, runs against whichever is
  canonical).
- If Plan 1 is chosen: the new consistency test fails against the current
  (broken) doc content and passes once the table is corrected — a genuine
  red→green cycle, not a static assertion written to match the fix after the
  fact.
