# 2. Tests

Eleven test functions were added across four packages, in six red→green slices.
All use the standard Go testing library with table-driven subtests.

## Seams — agreed before any test was written

The TDD skill is explicit about this:

> **Test only at pre-agreed seams.** Before writing any test, write down the
> seams under test and confirm them with the user. No test is written at an
> unconfirmed seam.

Four seams were proposed and **all four confirmed** before the first test:

| Seam | Boundary | Why it earns a test |
|---|---|---|
| 1 | `labelFor` / `derivedLabel` — the label decision | the defect itself, duplicated in two binaries |
| 2 | `SessionRecord.ToCSVRow` | the `nil → "0"` laundering step |
| 3 | exporter, CSV on disk | proves the whole chain, not the pieces |
| 4 | labeler, files on disk | the direct regression of "11 benign, 2 malicious" |

Seam 1 turned out to be best served by extracting the decision into a new
`internal/dataset` package that both binaries call, so its tests live there plus
in the validator; see [05-why-this-approach.md](05-why-this-approach.md).

---

## Slice 1 — `TestLookupResolvesGroundTruthForEachCorpusFixture`

Six subtests, one per corpus fixture, asserting label **and** category.

**On not being tautological.** The skill's rule is that expected values must
come from an independent source, not be recomputed the way the code computes
them. These expected values are written out by hand from what each fixture is
*documented to do* — `AUDIT.md`'s C4 names `crypto-miner-test`,
`env-stealer-test`, `ci-secret-grabber-test` and `reverse-shell-test` as
"genuinely malicious test fixtures", alongside `suspicious-test`; only
`benign-test` is benign. The test never calls the table to work out what the
table should say.

**Result: achieved.** Red (`undefined: Lookup`) → 6/6 pass.

## Slice 2 — `TestLookupRejectsUndeclaredPackages`, `TestLookupErrorNamesTheOffendingPackage`

Five subtests covering a real registry package (`lodash`), a versioned registry
package, an undeclared fixture, an empty spec, and a near-miss typo of a
declared name (`crypto-miner-tes`).

The assertion is deliberately two-part:

```go
if err == nil { t.Fatalf(...) }
if got.Label == 0 && got.Category == "benign" {
    t.Errorf("... an undeclared package must never look benign")
}
```

The property under test is not "unknown input returns an error code" — it is
**"an undeclared package can never be mistaken for a benign sample"**. That is
what C4 actually was: the old code always produced *an* answer, and its answer
was benign.

The RED output makes the danger concrete:

```
Lookup("lodash") = {Label:0 Category:}, nil; want an error for an undeclared package
```

A second test asserts the error names the offending package, because an operator
hitting this mid-capture needs to know *which* one without re-running.

**Result: achieved.** 6/6 pass.

## Slice 3 — `TestLabelDirectoryLabelsEveryCorpusFixtureCorrectly` (seam 4)

Copies the **real 13-file corpus** into `t.TempDir()` (the labeler rewrites
files in place, so the tracked originals are never touched), runs the real
`labelDirectory`, then re-reads every file off disk and asserts the label
written back matches ground truth — plus that the summary counts agree.

Expected labels come from a map written independently in the test file, not from
`dataset.Lookup`. A test that asked the production table what to expect would
pass by construction.

Skips cleanly if the corpus is unavailable.

**Result: achieved.** Red (`undefined: labelDirectory`) → pass.

## Slice 4 — `TestToCSVRowRefusesRecordWithNoLabel`, `TestToCSVRowUsesTheAssignedLabel` (seam 2)

The first asserts a nil-label record produces an error **and no row** — a row
returned alongside an error is still a row a careless caller can write.

The second asserts a labelled record still exports correctly, checking both the
`label` column and the `severity_score` column, at indices taken from the
documented column order in `ToCSVRow`'s own doc comment rather than from the
implementation.

**Result: achieved.** Red (signature mismatch) → 3/3 pass.

## Slice 5 — three `derivedLabel` tests (seam 1, validator half)

- `TestDerivedLabelPrefersTheStoredLabel` — a record with a stored label uses
  it, even when the table would say otherwise. The labeler is the authority; the
  validator validates what is *in* the dataset, not its own opinion of it. The
  test makes these deliberately disagree (`benign-test` with a stored `1`) so a
  precedence bug cannot hide behind agreement.
- `TestDerivedLabelFallsBackToDeclaredGroundTruth` — six subtests; an unlabelled
  record resolves through the shared table.
- `TestDerivedLabelRejectsUndeclaredPackage` — asserts the error wraps
  `dataset.ErrUnknownPackage`, checked with `errors.Is`.

**Result: achieved.** 8/8 pass.

## Slice 6 — `TestExportDirectoryWritesTheAssignedLabel`, `TestExportDirectoryRefusesUnlabelledSessions` (seam 3)

Both write real session JSON to a temp dir, run the real `exportDirectory`, and
parse the CSV **back off disk** with `encoding/csv` — verifying through the
artifact the ML pipeline actually consumes.

The second is the end-to-end statement of the whole fix: two unlabelled
malicious sessions and one labelled benign one go in; exactly one row comes out,
and the test asserts by name that neither malicious package reached the CSV.

**Result: achieved.** 2/2 pass.

---

## Goal coverage

| Goal | Covered by | Achieved |
|---|---|---|
| 1 — every fixture correctly labelled | Slice 1, Slice 3 | yes |
| 2 — undeclared package never guessed | Slice 2, Slice 5 | yes |
| 3 — labeler and validator cannot disagree | Slice 5 (shared table) | yes |
| 4 — no label ⇒ no training row | Slice 4, Slice 6 | yes |
| 5 — failures are loud | exit codes + validator Rule 4, shown in `evidence/pipeline-end-to-end.txt` | yes |
| 6 — nothing else changes | `-race` and root suites | yes |

## One pre-existing test required updating

`TestSessionRecord_ToCSVRow_LegacyUserlibAlias` built a record with no label, so
it began failing once `ToCSVRow` started refusing those. Its subject is the
`userlib_dir_access` column alias, not labelling, so it was given a label to
reach the columns it actually tests, with a comment saying why. This is recorded
here rather than passed over silently: it is a real, if small, change to an
existing test caused by this work.
