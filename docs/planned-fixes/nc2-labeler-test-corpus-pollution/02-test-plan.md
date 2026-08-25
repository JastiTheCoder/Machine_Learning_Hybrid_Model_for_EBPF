# 2. Test plan — NC2

This bug is unusual for this project's TDD convention: the "test" being fixed
*is itself part of the test suite*. The plan below therefore has two layers —
tests **of** the fix (does the labeler still label correctly) and a
**meta-test**, a reproduction harness proving the coupling itself is gone. Per
`skills/.agents/skills/tdd/`: seams confirmed first, vertical slices, red before
green.

## Seams to confirm with the user before writing any test

| Seam | Why this one |
|---|---|
| `TestLabelDirectoryLabelsEveryCorpusFixtureCorrectly` itself (the existing test, modified in place) | This *is* the bug's location; the fix is judged by this test's own behavior, not a new parallel test |
| The corpus source (`corpusDir` today, `testdata/corpus/` under Plan 1) as an independent, injectable-for-testing seam | Lets the meta-test (below) prove the decoupling without needing root or a real `monitor` binary run |
| `internal/dataset.Lookup` (already exists, unchanged) | The production ground-truth table this test's independence is checked against; not modified by this bug, but its `express`/`chalk`/`debug` entries are part of what this bug's fix must reconcile |

## Slice 1 — reproduce the failure exactly as observed (red, against current code, no source changes yet)

**Reproduction, not a new permanent test:** from a clean shell, add a junk file
to the live `sessions/` directory and run the existing test.

```sh
echo '{}' > sessions/zzz-audit-repro-junk.json
go test ./cmd/dataset/labeler/... -run TestLabelDirectoryLabelsEveryCorpusFixtureCorrectly -v
rm sessions/zzz-audit-repro-junk.json
```

**Expected before any fix:** **red** — `t.Fatalf` on the junk file's fixture
name not being in `expectedLabels`. Capture this transcript as evidence,
matching every prior `docs/bugs-fixed/*/evidence/*-red.txt`. This is also
exactly what already happened this session with the eleven real untracked
capture files — that transcript (captured during the audit) can serve as the
red evidence directly, with the junk-file version as an even more minimal,
reproducible-on-demand confirmation.

## Slice 2 — the meta-test: the suite is decoupled from `sessions/`'s live contents

**Test (new, permanent):** after Plan 1's migration (or Plan 2's skip-logic),
add a small script- or test-level check that the exact reproduction from slice 1
no longer fails:

```sh
echo '{}' > sessions/zzz-audit-repro-junk.json
go test ./cmd/dataset/labeler/... -run TestLabelDirectoryLabelsEveryCorpusFixtureCorrectly
rm sessions/zzz-audit-repro-junk.json
```

If this is worth codifying as a real Go test rather than a manual reproduction
step (recommended, so CI or a future contributor gets it for free): a small
`TestLabelerSuiteIsUnaffectedByExtraFilesInLiveSessionsDir` in a *different*
test file (not `main_test.go` itself, to avoid the test verifying its own
premise) that shells out to `go test` on the labeler package with a junk file
present, asserting exit code 0. This is unusual (a test that runs `go test`) but
directly proves the specific claim NC2 makes, the same way `docs/bugs-fixed/
fix-dead-detector-run/evidence/dry-run-confirmation.txt` proves a claim about
process-level behavior rather than only unit-level.

**Expected before any fix:** **red** (same failure as slice 1). **Expected after
either Plan 1 or Plan 2:** **green**.

## Slice 3 — the C4 regression guard is not weakened (teeth-check)

**Test:** temporarily corrupt one entry — under Plan 1, edit one fixture's
`"label"` field in the migrated `testdata/corpus/` set to the wrong value; under
Plan 2, temporarily edit one `expectedLabels` entry to the wrong value — and
re-run `TestLabelDirectoryLabelsEveryCorpusFixtureCorrectly`.

**Expected:** **red** — the test must still catch a genuinely wrong label. This
is not a new test; it's a manual teeth-check step to run once during
implementation and record the transcript, proving the decoupling didn't
accidentally neuter the original C4 guard. Revert the corruption immediately
after capturing the red evidence.

## Slice 4 — `labels.go`'s `express`/`chalk`/`debug` entries are reconciled, not left dangling

**Test:** if Plan 1's migration adds real `express`/`chalk`/`debug` fixtures to
the new `testdata/corpus/`, extend `expectedLabels` (or its Plan-1 equivalent)
to include them and assert they label correctly — a straightforward, non-red
addition alongside the existing `lodash` case, since `internal/dataset.Lookup`
already handles them correctly (confirmed: `labels.go:54-57`).

If the implementer instead decides not to add real fixtures for those three
(a legitimate call, per `01-bug.md`), this slice becomes a documentation note in
the new `testdata/corpus/README` (or equivalent) explaining the decision, not a
test — recorded here so the choice is deliberate, not an oversight repeating
root cause (b).

## Teeth-check plan

Slice 1 is the reproduction (red by construction against current code). Slice 3
is the explicit teeth-check for the regression guard. No timing/concurrency is
involved in this bug (it's pure file-I/O and static comparison), so no
fault-injection or repeated-trial harness is needed — a single deterministic
reproduction and a single deterministic corruption-and-revert are sufficient to
meet `CLAUDE.md`'s "reliably reproduce" bar here.

## Goal coverage

| Goal (from `01-bug.md`'s Expected result) | Covered by |
|---|---|
| `go test ./...` passes from a clean checkout | Baseline run, any slice |
| Passes even with an untracked junk file in `sessions/` | Slice 2 |
| Still fails on a genuinely wrong label (C4 guard intact) | Slice 3 |
| `express`/`chalk`/`debug` reconciled | Slice 4 |
