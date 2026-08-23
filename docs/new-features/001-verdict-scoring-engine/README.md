# New feature — a userspace verdict/scoring engine for completed installs

This directory documents one piece of work: adding a **weighted, evidence-backed
rule engine** that scores every completed npm-install session and produces an
explainable `benign` / `suspicious` / `malicious` verdict, on top of the
existing eBPF collection pipeline. The plan that scoped this work lives at
`/home/ani/.claude/plans/the-goal-of-this-cozy-trinket.md` and was approved
before any code was written; this doc set is its record, using the
test-driven workflow in `skills/.agents/skills/tdd/`.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | The nine stages, in the order they shipped. |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why this way and not the alternatives? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-findings-not-fixed.md](07-findings-not-fixed.md) | What was left open. |
| — | [evidence/](evidence/) | Raw, unedited output behind every claim made above. |

## One-paragraph summary

The daemon collected rich per-session evidence and threw almost all of it
away: `ProcessEvent.Args` was reduced to a bare `comm`, `TCPEvent`'s real
endpoints were reduced to set cardinalities, and `FileEvent.Filename` was
never even populated (`bpf/file_monitor.bpf.c` memset it unconditionally,
because the path never survived from the `openat()` enter probe to the exit
probe that emits the event). This work carries the path through
(`struct pending_open`, the one kernel-side change in the whole plan), adds a
bounded `EvidenceCollector` in userspace that classifies paths, argv shapes,
and endpoints into named indicators, and scores the result against twelve
weighted rules — two of them decisive (fire once, verdict is `malicious`
regardless of total score) — landing in a new `verdict` block in the session
JSON and a live `[ALERT]` line on `cmd/monitor`'s stdout. While wiring the
kernel-boundary path through to a real, root-gated end-to-end test (the
suite's first test to exercise the *decisive* `EXFIL-001` rule against real
kernel events rather than a hand-built `Input`), the work surfaced and fixed
a second, independent bug: `FileEvent.TimestampNs` was silently corrupted for
every file event ever decoded, because `encoding/binary.Read` does not
reproduce the C compiler's own struct-alignment padding. See
[03-what-was-done.md](03-what-was-done.md) for both.

## What shipped

- `internal/verdict` (new package): `Rule`, `Input`, `Evaluate`, a 12-rule
  default registry, `Derived` (install-size-normalized ratios).
- `internal/features/{evidence,pathclass,argvclass}.go` (new): a bounded,
  deduplicated per-session evidence collector, wired into `Session` under its
  existing lock.
- `bpf/file_monitor.bpf.c`: `struct pending_open` now carries the opened
  path from enter to exit probe, so `FileEvent.Filename` is finally
  populated.
- `internal/collector/file_collector.go`: a second, independent fix —
  `FileEvent` gained an explicit 4-byte padding field so `binary.Read`
  decodes `TimestampNs` from its real wire offset instead of 4 bytes early.
- `internal/output`: `SessionRecord.Verdict`, schema version `1.1.0`
  (additive, backward compatible).
- `cmd/monitor`: live `[ALERT]` line on stdout for any session banded
  malicious; `-suspicious-threshold`/`-malicious-threshold` flags.
- `internal/dataset/labels.go`: four real, unmodified npm-registry packages
  (`lodash`, `express`, `chalk`, `debug`) added as `benign-real-world` ground
  truth, used to calibrate three of the twelve rules against real installs
  rather than only the project's own six hand-written fixtures.
- A new root-gated end-to-end regression test,
  `TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert`, that
  drives the compiled `monitor` binary against a real npm install whose
  postinstall reads a credential-shaped path and then connects outbound to a
  test-local listener — the first test in this project to prove the decisive
  `EXFIL-001` rule end to end, through real kernel events.
