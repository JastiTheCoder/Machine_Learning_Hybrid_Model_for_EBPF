# 1. Bug — NC2: `go test ./...` fails whenever `sessions/` has an undeclared capture

Source finding: [`../../NEW_AUDIT.md`](../../NEW_AUDIT.md#nc2-go-test--currently-fails-and-the-failure-is-a-symptom-of-a-real-design-gap-not-a-fluke).

## How it came about

Two compounding causes, from two different commits:

**(a) The test was built to read the live, operational output directory
directly — from day one.** `cmd/dataset/labeler/main_test.go`'s
`TestLabelDirectoryLabelsEveryCorpusFixtureCorrectly` was added in commit
`e1d557c` ("Fix four audit findings: C1, C4, ProcessTracer load, fork tgid
lookup", 2026-08-22) as the direct regression test for the C4 mislabeling bug.
Its `corpusDir` constant (`main_test.go:12`) is `../../../sessions` — the
repository's real, tracked `sessions/` directory, which is *also*
`cmd/monitor`'s default `-output-dir` (`cmd/monitor/main.go:58`) for every real
capture run. `copyCorpusToTemp` (`main_test.go:35-63`) reads every `*.json` file
in that directory and `TestLabelDirectoryLabelsEveryCorpusFixtureCorrectly`
(`main_test.go:94-131`) `t.Fatalf`s on the first file whose fixture base name
isn't in the test's own hardcoded `expectedLabels` map. This was correct for the
exact 13-file corpus that existed on 2026-08-22, and has been a latent
design gap ever since — dormant only because nobody had captured anything new
into `sessions/` in this checkout until now.

**(b) A maintenance gap layered on top, one day later.** Stage 8 of the
verdict-engine work (commit `15f2b51`, 2026-08-23) added `express`, `chalk`, and
`debug` to the *production* ground-truth table,
`internal/dataset/labels.go`'s `fixtureLabels` (`labels.go:54-57`) — but only
added `lodash` to the test's independent `expectedLabels` map
(`main_test.go:22-33`; its own comment explains the independence is
deliberate: "If this duplicated the production table ... it would pass by
construction"). No `express`/`chalk`/`debug` fixture had actually been committed
to `sessions/` as of that commit, so this gap was inert — but it guaranteed the
same failure NC2 describes the moment anyone committed a real capture for any of
those three packages, independent of anything this audit's own session did.

**What actually triggered the currently-observed failure:** this audit session's
own use of the compiled monitor to capture several real and fixture packages
(`underscore`, `moment`, `axios`, `uuid`, `dotenv`, a second `suspicious-test`,
`persistence-test`, `ssh-reader-test`, plus fresh copies of `chalk`/`debug`) left
eleven untracked `*.json` files in `sessions/`, none declared in `expectedLabels`
— exactly the ordinary, intended use of the tool, and enough on its own, with
zero source changes, to fail `go test ./...`. Reproduced directly this session:

```
--- FAIL: TestLabelDirectoryLabelsEveryCorpusFixtureCorrectly (0.00s)
    main_test.go:116: corpus file npm-1787576926_suspicious-test.json has fixture
    "suspicious" with no expected label in this test; update expectedLabels
FAIL
```

## Candidate fixes

### Plan 1 (recommended) — hermetic fixture directory, decoupled from `sessions/`

Give the test its own fixture set the tool never writes to — e.g.
`cmd/dataset/labeler/testdata/corpus/` — populated once with copies of the
specific committed session files the test is meant to check (the original
13-file corpus, plus whichever of `lodash`/`express`/`chalk`/`debug` the
implementer decides should have a real captured fixture; see the open question
below). Point `corpusDir` at the new path. `copyCorpusToTemp` itself needs no
logic change — only the constant.

- **Also fixes (b):** while migrating the fixture set, add real
  `express`/`chalk`/`debug` captures (or, if none are readily available,
  explicitly decide and document whether those three stay in
  `internal/dataset/labels.go`'s ground-truth table without a corresponding
  committed test fixture — that's a legitimate choice, since `labels.go` and the
  test's fixture set no longer need to be in lockstep once they're decoupled).
- **Cost:** a one-time migration of files; needs a decision about which packages'
  captures are "the" canonical committed corpus going forward (worth flagging to
  the user during implementation rather than assuming).
- **Why recommended:** removes the coupling entirely and permanently — "run the
  tool" and "break this test" become unrelated actions, which is the actual
  defect (a) describes.

### Plan 2 — make the live-corpus scan resilient to unknown fixtures

Keep reading `sessions/` directly, but change the loop
(`main_test.go:110-116`) to `t.Logf` and `continue` (skip) rather than
`t.Fatalf` when a fixture's base name isn't in `expectedLabels`, and separately
assert that every file whose name *is* declared carries the correct label.

- **Cost:** weaker guarantee — a newly captured, mislabeled fixture that
  *happens* to share a name already in `expectedLabels` is still caught, but any
  genuinely new fixture silently stops being checked until a human remembers to
  add it to the map. This is close to the exact failure mode C4 itself was: a
  silent gap in what gets validated.
- **Benefit:** smaller diff; keeps the "check the real, evolving corpus" intent
  Plan 1 gives up.
- **Not recommended as primary** because it doesn't remove root cause (a) — the
  test's pass/fail status still depends on `sessions/`'s live contents, just
  with a softer failure mode; a future dataset consumer (e.g. `validator`) could
  still be silently affected by the same directory-dual-role problem in ways
  this specific test would no longer surface.

## Expected result

- `go test ./...` passes from a clean checkout.
- `go test ./cmd/dataset/labeler/...` (and the full suite) still passes after
  adding an arbitrary untracked junk `*.json` file to `sessions/` — verify this
  literally, by creating and removing such a file around the test run, as the
  direct falsification of "the test no longer depends on `sessions/`'s live
  contents" (Plan 1) or "an unknown fixture no longer fails the run" (Plan 2).
- The test must still fail if a *known* fixture's label is wrong — i.e., the C4
  regression guard this test exists for is not weakened by decoupling it. Proven
  by a teeth-check: temporarily flip one `expectedLabels` (or fixture-set) entry
  to the wrong value, confirm the suite goes red, then revert.
- `internal/dataset/labels.go`'s `express`/`chalk`/`debug` entries and the test's
  fixture set are brought into an explicit, documented relationship (either both
  covered by a real committed fixture, or explicitly noted as declared-but-not-
  yet-fixtured) — closing root cause (b) as a side effect, not left implicit.
