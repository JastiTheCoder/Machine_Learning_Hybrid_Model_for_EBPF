# Fix — C4: malicious fixtures exported to the training set labelled benign

This directory documents one piece of work: repairing **C4**, one of the four
Critical findings in [`../../AUDIT.md`](../../AUDIT.md), using the test-driven
workflow in `skills/.agents/skills/tdd/`.

Read the documents in order — they follow the sequence the work happened in.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | The six red→green slices, in order. |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why this way and not the alternatives? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-findings-not-fixed.md](07-findings-not-fixed.md) | What was left undone, and why. |
| — | [evidence/](evidence/) | Raw, unedited output behind every claim made above. |

## One-paragraph summary

The labeler assigned `label=1` only when a session's filename or `package_name`
contained the literal substring `"suspicious"`. Four of the five
attack-simulation fixtures — `crypto-miner-test`, `env-stealer-test`,
`ci-secret-grabber-test`, `reverse-shell-test` — do not contain it, so they
defaulted to `label=0`. The validator duplicated the same heuristic
independently, so it agreed. `ToCSVRow` then turned a missing label into a
confident `"0"`, and the exporter wrote it to the training CSV with no warning.

Measured against the project's own 13-session corpus: the labeler reported
**"11 benign, 2 malicious"** where ground truth is **3 benign, 10 malicious** —
**8 of the 10 malicious samples were labelled benign**. A Random Forest trained
on that CSV would have been taught that a reverse shell, a crypto miner, a
credential stealer and a CI secret grabber are all normal `npm install`
behaviour. This is the exact signal the entire project exists to produce.

The fix introduces `internal/dataset`, a declared fixture → ground-truth table
that both the labeler and the validator now share, and which **refuses** an
undeclared package instead of guessing. `ToCSVRow` refuses a record with no
label, the exporter excludes those rows and exits non-zero, and the validator
gained a Rule 4 that fails when any session lacks a resolvable label.

After the fix, the same corpus labels **3 benign, 10 malicious**, and the
exported CSV carries that distribution exactly.

## Reproducing the "before" number

The pre-fix result is independently re-runnable rather than quoted from a
transcript — see
[`evidence/pre-fix-heuristic-reproduction.txt`](evidence/pre-fix-heuristic-reproduction.txt)
and the standalone program described in [04-how-it-was-done.md](04-how-it-was-done.md).
