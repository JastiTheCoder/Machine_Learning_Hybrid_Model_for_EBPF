# 7. Findings not fixed

## A. `BuildRecord` still never sets `Session.Label` — Low, by design

Every session JSON is written with `"label": null` and only becomes labelled
when the labeler runs over the directory afterwards. That two-step flow is
unchanged by this work.

**Why not fixed:** the monitor genuinely does not know the label at capture
time. It observes an `npm install`; whether that package is malicious is an
external fact supplied by whoever assembled the corpus. Making the monitor
assign labels would push the ground-truth table into the capture path and invite
exactly the coupling this fix removes.

What *has* changed is that an unlabelled record can no longer be mistaken for a
benign one — it is now refused at export with a message naming the file. The
two-step flow is fine; it was the silent third step that was the bug.

## B. `Category` is recorded but never exported — Low

`FixtureLabel.Category` (`cryptomining`, `credential-theft`, `remote-access`,
…) is used for the labeler's console output and for making the table
self-documenting. It is not written into the session JSON and not exported to
the CSV.

**Why not fixed:** no test demanded it, and the TDD skill is explicit — "only
enough code to pass it. Don't anticipate future tests or add speculative
features." Adding a column to a 39-column CSV that an ML team already consumes
is a schema change that deserves its own conversation, not a side effect of a
labelling fix.

**Worth doing if** the classifier ever moves from binary to multi-class, at
which point the category is already declared and just needs plumbing.

## C. The capture-time provenance field from C4's fix direction — Medium, deferred

`AUDIT.md` suggested embedding `severity`/`category` at capture time as an
alternative to the table. The table was chosen because it fixes the already
captured corpus (see [05-why-this-approach.md](05-why-this-approach.md)).

The capture-time field remains genuinely valuable for one thing the table cannot
do: a session file that travels away from this repository carries no provenance,
so its label depends on a table it can no longer see.

**Suggested shape:** have the monitor accept an optional `--label`/`--category`
flag, written into the record at capture time, with `internal/dataset` remaining
the authority when that flag is absent.

## D. Fixture name collisions are possible in principle — Low

`fixtureKey` strips a trailing dotted-numeric version, so
`crypto-miner-test-1.0.0.tgz` and `crypto-miner-test-2.0.0.tgz` intentionally
collapse to the same key — that is the desired behaviour for versions of one
fixture. It also means a genuinely different package that happened to be named
`crypto-miner-test` would silently inherit the fixture's label.

**Why not fixed:** the corpus is a controlled set of locally built tarballs, not
arbitrary registry content, so this requires someone to deliberately name a
package after an existing fixture. Guarding it would mean hashing tarball
contents, which is a much larger mechanism than the risk warrants.

## E. The exported CSV's `severity_score` is still just a copy of `label` — Low

`ToCSVRow` sets `severity_score` to the same string as `label`, per its existing
comment ("mirrors label for ML team baseline"). This fix corrected *what* that
value is, but did not make it a genuine severity.

**Why not fixed:** out of scope, and it is a question for whoever owns the ML
schema — a real severity scale would need defining before it could be populated.
The `Category` field in the table is the natural input if that happens.

---

## Still open from earlier work

- **C2 — `BuildRecord` reads session state with no locking.** Critical, still
  open. Can crash the process with `fatal error: concurrent map writes`.
- **C3 — a session can be completed twice.** Critical, still open. Timeout vs.
  normal-exit race producing duplicate output.
- **`bpf/vmlinux.h` is stale** relative to the running kernel; regenerating
  needs `bpftool`.
- **`llvm-strip` is not installed**, so `go generate ./internal/collector/...`
  needs `BPF2GO_STRIP=/usr/bin/strip`.
- **The fork handler's insert side** can write a TID into the tgid-keyed map on
  `CLONE_THREAD` — see
  [`../fix-fork-tgid-lookup/07-findings-not-fixed.md`](../fix-fork-tgid-lookup/07-findings-not-fixed.md).
