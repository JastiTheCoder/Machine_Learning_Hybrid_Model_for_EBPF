# 1. Goals

## The defect

`AUDIT.md` C4, verbatim in substance:

> `cmd/dataset/labeler/main.go`'s `labelFor` only assigns `label=1` (malicious)
> if the session's filename or `package_name` contains the literal substring
> `"suspicious"`. The four attack-simulation fixtures added alongside it —
> `crypto-miner-test`, `env-stealer-test`, `ci-secret-grabber-test`, and
> `reverse-shell-test` — do **not** contain that substring, so they default to
> `label=0` (benign).

Three separate mechanisms had to line up for this to be as bad as it was, and
all three were present:

1. **The labeler guessed.** `labelFor` returned `0` for anything it did not
   recognise. There was no "unknown" outcome, so a fixture nobody had thought
   about was silently benign.
2. **The validator duplicated the guess.** `derivedLabel` in
   `cmd/dataset/validator/main.go` reimplemented the same substring heuristic
   independently, so it produced the same wrong answer and could never
   contradict the labeler.
3. **The exporter laundered the guess into data.** `ToCSVRow` turned
   `Label == nil` into `"0"`, and mirrored it into `severity_score`. The
   exporter wrote the row with no warning.

`BuildRecord` never sets `Session.Label` at all, so every one of the 13 files in
`sessions/` carries `"label": null` — confirmed by direct grep. That means
mechanism 3 was not a fallback path, it was *the* path.

## The measured blast radius

Run against the project's own corpus, the pre-fix heuristic produces:

```
PRE-FIX RESULT: 11 benign, 2 malicious (13 total)
GROUND TRUTH:   3 benign, 10 malicious (13 total)
MISLABELLED:    8 malicious samples labelled benign
```

80% of the malicious training samples were labelled benign.

## Why this was chosen as the highest-severity remaining item

Three Critical findings were still open: C2 (unlocked concurrent read in
`BuildRecord`), C3 (double session completion), and C4.

C2 and C3 are races. They are real, but they require a specific timing window,
and when they do fire they are comparatively loud: C2 crashes the process with
`fatal error: concurrent map writes`, C3 produces a visible duplicate file.

C4 is **deterministic and silent**. It fired on every run, for 8 of 13 files,
and produced output that looks completely normal — a mislabelled row still has
legitimate non-zero behavioural features, so neither the validator's "no
all-zero features" rule nor any other check could catch it. The audit's own
assessment: *"A silent benign-mislabel of real malicious samples is worse than a
crash: it actively corrupts the dataset with no diagnostic trail."*

## Goals

1. **Every corpus fixture gets its correct label.** No substring heuristics.
2. **An undeclared package is never guessed at.** It must produce an error, and
   in particular must never come back looking benign.
3. **The labeler and validator must not be able to disagree.** One source of
   truth, shared, rather than two independent reimplementations.
4. **A record with no label cannot become a training row.** The `nil → "0"`
   default must go.
5. **Failures must be loud.** Exit non-zero, name the offending file, and say
   what to do about it.
6. **Nothing else changes.** No collector, no BPF, no session schema.

## How we would know

- Goal 1 → `dataset.Lookup` resolves each of the six corpus fixtures to an
  independently-written expected label; plus the labeler run end-to-end over the
  real corpus.
- Goal 2 → `Lookup` returns an error for undeclared packages, asserted to not
  also return a benign-looking value.
- Goal 3 → the validator's `derivedLabel` resolves through the same table.
- Goal 4 → `ToCSVRow` returns an error for a nil label; the exporter excludes
  the row from the CSV on disk.
- Goal 5 → exporter and labeler exit non-zero; validator gains a failing rule.
- Goal 6 → full repository suite, `-race` and under root.
