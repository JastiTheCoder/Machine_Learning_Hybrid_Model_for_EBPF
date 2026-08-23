# 4. How it was done

The nine stages, in the order they actually shipped, each gated on the full
repository suite (unprivileged, then root) before moving to the next. This is
the narrative of *what happened and why in that order*; [02-tests.md](02-tests.md)
covers the same ground from the tests' point of view.

## Stage 0 — baseline, seams, no production code

Before writing anything, the six seams under test (later seven — see
[02-tests.md](02-tests.md)) were written down and the full suite's "before"
state captured. This matters here specifically because two of this plan's
nine stages touch kernel code or its decode boundary, and CLAUDE.md requires
stating up front whether a test proves something at the verifier/compile
level or requires a real load/run — that distinction had to be decided per
seam before any test existed, not retrofitted afterward.

## Stage 1 — kernel: carry the path through `pending_open`

The plan called this "the only kernel-side change," and it was scoped that
narrowly on purpose: `struct pending_open` gains one field, one `memcpy`
replaces one `memset`. Nothing else in `bpf/file_monitor.bpf.c`, and no other
BPF program, was touched. The root-gated test
(`TestFileCollectorReportsFilenameFromRealOpenat`) was written first and
confirmed red against `HEAD` (empty filename, since the `memset` was
unconditional) before the fix landed — a real red, not an assumed one.

This stage shipped in an earlier part of this overall session, before the
compaction this doc set was finished under; its diff was re-gathered fresh
from `git diff` for [03-what-was-done.md](03-what-was-done.md) rather than
recalled from memory, to make sure the doc reflects the code as it actually
is.

## Stage 2 — `verdict` core, one rule

`Evaluate`, `Rule`, `Input`, `Verdict`, `Finding`, `Thresholds` were built
around exactly one rule (`NET-003`, a ratio) — deliberately not the full
twelve, so the shape of scoring and banding got proven before there was
anything to distract from it. Three vertical slices: below threshold, above
threshold, banding at the boundary.

## Stage 3 — registry, decisive rules, determinism

The registry pattern (`MustRegister`, panic on duplicate ID) and the
decisive-rule short-circuit were added next, still against a small rule set,
because both needed to be proven correct before eleven more rules made a
registry bug harder to isolate. `Findings` ordering (weight desc, then ID
asc) was locked down here specifically so a later stage's output tests could
assert on exact JSON rather than an unordered set.

## Stage 4 — `features.EvidenceCollector`

With the scoring engine's shape proven, the evidence side was built next,
independently: `pathclass.go`, `argvclass.go`, `evidence.go`. This stage
produced the bulk of the near-miss negative tests in the whole plan — every
`PathClass` needed a "looks similar but isn't" case (`.ssh/known_hosts`
next to `.ssh/id_rsa`), since a scoring engine that fires on the wrong
signal is worse than one that fires on nothing.

## Stage 5 — wire evidence into `Session`

`Session.AddProcess`/`AddFile`/`AddTCP` were extended to feed the new
collector under `s.mu`, the same lock every other aggregator already uses.
The race test here (`-race`, ≥1000 iterations of concurrent
`AddFile`/`AddProcess`/`AddTCP` against a concurrent `Snapshot()` loop) was
deliberately proven to have teeth before trusting it: the evidence field was
temporarily exposed outside the lock, `-race` was confirmed to catch that,
and only then was the exposure removed again. A race test that has never
actually failed on a broken version proves nothing about the fixed one.

## Stage 6 — the full rule set

The remaining ten rules were added, each its own red→green slice, each with
a positive and a near-miss negative. `EXFIL-001` — the ordered
credential-read-then-connect rule — got disproportionate attention here
because it is one of only two decisive rules and its correctness rests
entirely on `firstSeen` ordering, not just presence: forcing both orderings
explicitly, plus each fact alone, was non-negotiable per CLAUDE.md's own
standard for anything timing-dependent.

## Stage 7 — output surface

`SessionRecord.Verdict`, schema `1.1.0`, and the live `[ALERT]` line were
added last among the "shape" stages, once there was a stable verdict to
attach to a record. The feature-subtree-byte-identical test
(`TestBuildRecordFeatureFieldsUnaffectedByVerdict`) exists because this is
the one stage with a real chance of silently breaking the ML team's contract
— CLAUDE.md is explicit that this project's owner does not touch the ML
side, so proving the boundary is untouched, not just claiming it, was the
point.

## Stage 8 — recapture and calibrate

The only stage that is not a red→green slice: real, unmodified packages
(`lodash`, `express`, `chalk`, `debug`) were added to `internal/dataset`'s
ground truth, captured for real through the compiled binary, and three
rules' thresholds were adjusted directly against what that data showed —
`CRED-001` dropping `.npmrc` (a 100% false-positive rate against real
installs), `PROC-003`'s ratio baseline, and `DROP-001`'s writer-count
threshold. Each change is commented in `internal/verdict/rules.go` with the
specific numbers that justified it, per the plan's explicit requirement that
weights come from data, not guesses.

## Stage 9 — end-to-end regression, and an unplanned second bug

The plan's final stage was meant to be the closing proof: one root-gated
test driving the real binary against a real npm install, checking the
written JSON and the live alert. It was that — but it also surfaced a bug
none of the prior eight stages had reason to find: `FileEvent.TimestampNs`
had been silently corrupted by a `binary.Read`/C-struct-alignment mismatch
since the field was first written, invisible until this stage made the
first thing in the project depend on that field's numerical correctness
(`EXFIL-001`'s ordering check). Investigating and fixing it — rather than
loosening the test's assertions to route around it — is documented in full
in [02-tests.md](02-tests.md)'s Stage 9 narrative and
[03-what-was-done.md](03-what-was-done.md)'s per-file breakdown.

Docs were written last, after the code and every gate were confirmed green,
following the reference doc's structure (`docs/bugs-fixed/fix-pending-opens-leak/`)
rather than inventing a new one.
