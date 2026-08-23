# 5. Why this approach

## A weighted rule engine, not a second ML model

The plan's own framing was explicit: this is a fast, explainable pre-screen
that complements the ML team's classifier, not a competitor to it. A
weighted rule engine (the same shape as risk-based alerting in SIEM/EDR
tooling) was chosen over a second learned model for three reasons specific
to this project:

- **CLAUDE.md's ownership boundary.** This project's owner is responsible
  for the eBPF/kernel-boundary side and explicitly not the ML model. A
  second learned model would blur that line; a rule engine with named,
  citable rules does not.
- **Explainability is the point, not a side effect.** Every `Finding`
  carries a rule ID, a weight, a MITRE ATT&CK technique reference, and a
  human-readable reason. A malicious verdict with no story behind it is not
  more useful than the ML model's own score.
- **The corpus cannot train anything credible.** Six hand-written fixtures
  (one of which itself makes a real outbound call in its own postinstall)
  plus four real packages is nowhere near enough data to fit a model
  without massively overfitting. It is enough to calibrate a dozen weights
  by hand, with each one's justification written down (Stage 8; see
  [03-what-was-done.md](03-what-was-done.md)).

## Two-tier: decisive + accumulative, not accumulative alone

A pure weighted-sum model needs every signal to be individually weak enough
not to false-positive alone, which means a single unambiguous signal (a
credential read immediately followed by an outbound connection) gets
diluted into "one of several contributing factors" rather than treated as
what it actually is: conduct with no benign explanation for an npm install
script. Decisive rules exist so that `EXFIL-001` and `PERSIST-001` can each
independently force `malicious`, regardless of what else did or didn't fire
— without also making every other, weaker signal decisive and flooding the
verdict with false positives.

## Evidence lives in `internal/features`, not `internal/verdict`

The plan's dependency graph is deliberate: `verdict` only imports `features`,
never `session`. `session` already imports `features` to hydrate its other
aggregators (`DirCounts`, `TCPAggregator`), so putting `EvidenceCollector`
there keeps the graph acyclic without a redesign — `verdict.Input` is built
from plain feature types, and `session` hydrates evidence the same way it
already hydrates everything else. Putting evidence in `verdict` instead
would have forced `verdict` to import `session` (to be hydrated) while
`output` also needs to import both — not itself a cycle, but a needless
extra edge for no benefit, and a deviation from the existing
`FiletopAggregator`/`DirCounts`/`TCPAggregator` pattern this codebase
already uses everywhere else.

## Suffix-based path matching, not `$HOME`-relative

`ClassifyPath` matches by string suffix (`/.ssh/id_rsa`, `/.npmrc`, …)
rather than resolving `$HOME` and comparing paths relative to it. This
avoids a whole category of bugs (which user's `$HOME`? what if the
tracked process's environment lies about it? symlinked home directories?)
for a case where the suffix alone is already unambiguous — nobody has a
legitimate reason to name a file `.ssh/id_rsa` that isn't an SSH private
key, wherever it lives. It also makes the evidence collector trivially
testable without faking a filesystem layout, which is why Stage 4's tests
place fixture files anywhere convenient under `os.TempDir()`.

## Install-size-normalized ratios (`Derived`), not raw counts

Raw counts (`network_ops`, `process_ops`) scale with the size of the
install: a 400-dependency install legitimately makes far more syscalls than
a 1-dependency one, so a fixed threshold on the raw count either fires
constantly on large installs or never on small malicious ones. `Derived`
computes ratios (`network_ops / total_syscalls`, `process_ops /
direct_dependencies`) so the same threshold is meaningful across install
sizes — and returns zero rather than `NaN`/`Inf` when a denominator is
zero, so a rule evaluating a ratio never has to special-case a
divide-by-zero itself.

## Rides the existing `Session.Snapshot()` contract, not a parallel one

Evidence is hydrated inside the same single `s.mu` acquisition every other
aggregator's snapshot already uses. The alternative — a second lock, a
second snapshot method, or a separate evidence-only read path — was
rejected outright: this project already has one coherent-read contract
(the C2 fix this same overall effort's earlier work established), and
adding a second one is exactly the kind of thing that reintroduces a C2-shaped
bug rather than avoiding one. The Stage 5 race test exists specifically to
prove this discipline holds, not merely assumed to.

## Verdict as an additive JSON block, not a schema break or a second tool

The plan explicitly ruled out a CSV `severity_score` change and a new CLI
tool. `SessionRecord.Verdict` is a new, optional field; `schema_version`
bumped additively (`1.0.0` → `1.1.0`); a legacy record with no `verdict` key
still unmarshals with `Verdict == nil`. This keeps `internal/dataset`'s
labeler/validator/exporter paths — which read the existing corpus and feed
the ML team — untouched, which is the one hard constraint CLAUDE.md places
on this entire piece of work.

## What was considered and rejected

- **A single global score with no per-rule breakdown** — rejected: loses
  the explainability that is this feature's entire reason for existing.
- **Weights guessed from intuition rather than calibrated** — rejected per
  the plan's explicit decision; Stage 8 exists because six hand-written
  fixtures cannot calibrate anything credible on their own, and "trust the
  guess" was not accepted as good enough for a security tool.
- **Fixing `FileEvent.TimestampNs` as a separate, deferred item** — considered,
  since it is not a named `AUDIT.md` finding and CLAUDE.md's literal scope
  language references `AUDIT.md` items specifically. Rejected because the
  bug lives inside code this very task built and depends on (Stage 1's
  filename plumbing and Stage 9's own end-to-end test), and leaving a
  known-broken field in code this task ships would make the new
  `EXFIL-001` end-to-end proof dishonest. See
  [07-findings-not-fixed.md](07-findings-not-fixed.md) for the fuller
  reasoning on where that scope line was drawn.
