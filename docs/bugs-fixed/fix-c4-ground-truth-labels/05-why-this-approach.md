# 5. Why this approach

## Why a declared table rather than a capture-time field

`AUDIT.md` offered both: an explicit fixture→label mapping, or embedding a
`category`/`severity` field into the session JSON at capture time.

The table was chosen because it **fixes the corpus that already exists**. The 13
captured sessions are real data that took real `npm install` runs against real
attack simulations to produce; the capture-time approach cannot label any of
them without re-capturing everything. It also concentrates the ground truth in
one reviewable place — a reader can see the entire labelling policy in twelve
lines and disagree with it if they want to, which is exactly the property you
want from a training label.

The capture-time field is not wrong, and it is genuinely better in one respect
(a session becomes self-describing, so a file that travels away from this
repository keeps its provenance). It is recorded as an available extension in
[07-findings-not-fixed.md](07-findings-not-fixed.md) rather than built
speculatively.

## Why an undeclared package is an error rather than a default

This is the actual fix. The substring heuristic's problem was never that it
computed a wrong answer — it was that it **always computed an answer**, and its
fallback was the most dangerous of the two possible values.

Any design that keeps a default keeps the bug in a new costume. Default to
benign and a new attack fixture is silently mislabelled again. Default to
malicious and every legitimate registry package captured for comparison becomes
a false positive — and the failure is at least loud, but it is still a guess
presented as ground truth.

Refusing means an unrecognised package stops the pipeline until a human writes
down what it actually is. For a training label that is the only defensible
behaviour: the cost is one line in a table, and the alternative is silently
poisoned data.

This is why the slice-2 test asserts two things rather than one — that an error
comes back, *and* that what comes back alongside it does not look benign. An
error a caller ignores must still fail safe.

## Why the zero value's Category is deliberately not "benign"

`FixtureLabel{}` has `Label: 0`. That is unavoidable — Go's zero value for `int`
is 0, and 0 means benign in this schema. It cannot be designed away.

What *can* be designed is the second field. `Category` is `""` in the zero value
and `"benign"` only for the genuinely benign fixture, so the two are
distinguishable, and the test asserts on exactly that distinction. It is a small
thing, but it is the difference between "a caller who ignores the error gets
something ambiguous" and "a caller who ignores the error gets something that
looks like real ground truth".

## Why the labeler and validator now share a package instead of both being fixed

They were two independent implementations of the same rule, and they agreed —
which is worse than disagreeing, because agreement between two reimplementations
reads as corroboration. A reviewer checking the validator against the labeler
would have found them consistent and concluded both were right.

Fixing them separately would have restored that same structure: two
implementations, correct today, free to drift tomorrow. Extracting
`internal/dataset` means there is exactly one place the rule lives, and the
validator's job goes back to what it should be — checking the dataset, not
holding a second opinion about it.

## Why the validator still prefers a stored label over the table

If the labeler has run, the dataset's labels *are* the thing under validation.
A validator that re-derived them from the table would be checking the table
against itself and would never notice a corrupted or hand-edited file.

`TestDerivedLabelPrefersTheStoredLabel` makes this concrete by constructing a
record where the two deliberately disagree — a `benign-test` package carrying a
stored label of `1`. If precedence were the wrong way round the test fails; if
the test used a record where table and stored label agreed, it would pass either
way and prove nothing.

## Why the exporter skips rather than aborts

Consistent with [`../fix-silent-write-failures/`](../fix-silent-write-failures/):
one bad file should not discard the work of the good ones. The export still
produces a CSV containing every valid row, so a user with 200 sessions and 3
undeclared packages gets 197 usable rows plus a precise list of what to fix —
rather than nothing.

What makes that safe is the exit code. Skipping silently would be the original
bug again; skipping loudly, with `EXCLUDED <file>: <reason>` per row and a
non-zero exit, means a scripted pipeline stops even though the artifact was
written.

## Why tests parse the CSV back off disk

Seam 3 was confirmed as "the CSV on disk" rather than "the row `ToCSVRow`
returns" because the artifact the ML pipeline consumes is a file, and the
failure being fixed was about what ends up *in* that file. Asserting on the
in-memory row would have left the CSV writing untested, which is where a
column-order or quoting mistake would live.

## Why the "before" measurement was reimplemented rather than quoted

The single most important number in this document is `11 benign, 2 malicious`,
and by the time the documentation was written the code that produced it had been
deleted. A quoted transcript is not checkable — a reader has to trust that I
copied it correctly and that it came from the code I claim it did.

Reimplementing the old five-line heuristic as a standalone program and running
it against the real corpus makes the headline claim independently re-runnable by
anyone reading this. That cost about ten minutes and is the difference between a
documented result and an asserted one.
