# 4. How it was done — six vertical slices

The TDD skill is explicit that bulk-writing tests is an anti-pattern:

> **Horizontal slicing**: writing all tests first, then all implementation. […]
> Work in **vertical slices** instead: one test → one implementation → repeat,
> each test a **tracer bullet** that responds to what the last cycle taught you.

So this was done as six slices, each one test → run red → minimal
implementation → run green. Every red is recorded in `evidence/`.

## Step 0 — confirm the defect empirically, before writing anything

The audit's claim was taken as a hypothesis, not a fact. First:

```
$ grep -h '"label"' sessions/*.json | sort | uniq -c
     13   "label": null,
```

Then the labeler was run over a **copy** of the corpus (it rewrites in place):

```
Dataset: 11 benign, 2 malicious (13 total)
```

Ground truth is 3 benign / 10 malicious. The defect was real and worse than the
audit's prose conveyed — the audit said four fixtures were affected; measured,
that is 8 of 13 *files*, or 80% of the malicious samples.

## Step 0b — confirm seams with the user

The skill forbids writing a test at an unconfirmed seam. Four seams were
proposed with rationale, along with two design decisions that genuinely changed
the work (declared table vs. capture-time field; error vs. warn on a nil label).
All four seams were confirmed and both decisions settled before any test existed.

This is a deliberate correction of the previous task in this series, where the
seam was chosen unilaterally.

---

## Slice 1 — `Lookup` resolves declared fixtures

**Red:**
```
internal/dataset/labels_test.go:62:16: undefined: Lookup
FAIL	github.com/aniruddha/npm-ebpf-monitor/internal/dataset [build failed]
```

**Minimal green:** the table, `fixtureKey` normalisation, and

```go
func Lookup(packageSpec string) (FixtureLabel, error) {
	return fixtureLabels[fixtureKey(packageSpec)], nil
}
```

Deliberately minimal — it always returns `nil` error. That is *not* the finished
behaviour, and it is not meant to be: the skill says "only enough code to pass
it. Don't anticipate future tests." The missing error handling is what slice 2
exists to drive out, and leaving it absent here means slice 2 has a genuine red
rather than a formality.

Evidence: [`slice1-red.txt`](evidence/slice1-red.txt),
[`slice1-green.txt`](evidence/slice1-green.txt).

## Slice 2 — `Lookup` refuses undeclared packages

**Red** — and this is the slice whose red output is worth reading, because it
*is* the bug:

```
Lookup("lodash") = {Label:0 Category:}, nil; want an error for an undeclared package
Lookup("keylogger-test-1.0.0.tgz") = {Label:0 Category:}, nil; want an error ...
```

A confident zero, no error. Exactly what shipped.

**Green:** `ErrUnknownPackage` plus a wrapped error naming the spec, the resolved
key, and the file to edit.

Evidence: [`slice2-red.txt`](evidence/slice2-red.txt),
[`slice2-green.txt`](evidence/slice2-green.txt).

## Slice 3 — the labeler, end to end, on the real corpus

**Red:** `undefined: labelDirectory`.

**Green:** `labelFor` deleted; `main` split into `labelDirectory` + a thin
wrapper.

Immediately after, the real binary over a real corpus copy:

```
Dataset: 3 benign, 10 malicious (13 total)
```

Evidence: [`slice3-red.txt`](evidence/slice3-red.txt),
[`slice3-green.txt`](evidence/slice3-green.txt).

## Slice 4 — `ToCSVRow` refuses a nil label

**Red:** `assignment mismatch: 2 variables but record.ToCSVRow returns 1 value`.

**Green:** signature changed to `([]string, error)`.

This slice had a consequence the previous slices did not: changing the signature
broke `cmd/dataset/exporter`, and a pre-existing test. Both were repaired inside
this slice to keep the tree building — the exporter minimally (just enough to
compile; its *behaviour* is slice 6), and
`TestSessionRecord_ToCSVRow_LegacyUserlibAlias` by giving it a label, since its
subject is a column alias rather than labelling.

Evidence: [`slice4-red.txt`](evidence/slice4-red.txt),
[`slice4-green.txt`](evidence/slice4-green.txt).

## Slice 5 — the validator shares the table

**Red:** three `assignment mismatch` errors on `derivedLabel`.

**Green:** `derivedLabel` returns `(int, error)`, prefers a stored label, else
resolves through `dataset.Lookup`. Added Rule 4 and wired it into the final
gate.

Evidence: [`slice5-red.txt`](evidence/slice5-red.txt),
[`slice5-green.txt`](evidence/slice5-green.txt).

## Slice 6 — the exporter, verified through the CSV on disk

**Red:** `undefined: exportDirectory`.

**Green:** extracted `exportDirectory` returning `exportSummary{rows, skipped}`;
`main` exits non-zero when anything was excluded.

Evidence: [`slice6-red.txt`](evidence/slice6-red.txt),
[`slice6-green.txt`](evidence/slice6-green.txt).

---

## Step 7 — make the "before" number independently reproducible

Quoting `11 benign, 2 malicious` from a terminal I had already replaced would
have made the headline claim of this document unverifiable. So the pre-fix
heuristic was reimplemented as a standalone program outside the repository and
run against the real corpus:

```
PRE-FIX RESULT: 11 benign, 2 malicious (13 total)
GROUND TRUTH:   3 benign, 10 malicious (13 total)
MISLABELLED:    8 malicious samples labelled benign
```

Evidence: [`pre-fix-heuristic-reproduction.txt`](evidence/pre-fix-heuristic-reproduction.txt).

## Step 8 — verify the repository

```
$ gofmt -l …            (clean)
$ go vet ./...          (clean)
$ go build ./...        BUILD OK
$ go test -race ./... -count=1              all ok (9 packages)
$ sudo -n /usr/bin/go test ./... -count=1   all ok (9 packages)
```

Evidence: [`race-suite.txt`](evidence/race-suite.txt),
[`root-suite.txt`](evidence/root-suite.txt).

## Step 9 — run the whole pipeline the way an operator would

Export → label → validate → export, over a copy of the real corpus:

1. **Export before labelling:** `Wrote 0 rows`, 13 excluded, **exit 1**. Before
   the fix this step would have written 13 rows, every one labelled `0`.
2. **Label:** `Dataset: 3 benign, 10 malicious (13 total)`.
3. **Validate:** `PASS`, including the new
   `Rule 4: All files have a declared ground-truth label ✓`.
4. **Export after labelling:** `Wrote 13 rows`.

Evidence: [`pipeline-end-to-end.txt`](evidence/pipeline-end-to-end.txt),
[`exported-csv-labels.txt`](evidence/exported-csv-labels.txt),
[`dataset-after-fix.csv`](evidence/dataset-after-fix.csv).
