# Retiring QUT-DV25 as a Training Source

**Date:** September 17, 2026
**Author:** Karthik (ML Team)
**Status:** Decision record — QUT-DV25 is no longer used to train the npm detection model.

---

## Decision

QUT-DV25 is retired as a training source for the npm supply-chain detector. It is not
being patched, domain-adapted, or reweighted. The dataset remains on disk as evidence
for the analyses below, and `train_on_qut.py` is kept as a reproducible record of the
failed experiment, but no future model is trained on it.

The replacement is data captured by our own eBPF monitor, on npm, on one machine,
under one measurement methodology.

---

## What was attempted

`train_on_qut.py` trained Random Forest and XGBoost on all 14,271 QUT-DV25 samples
(7,144 benign PyPI packages, 7,127 malicious) using a 37-feature vector mapped onto
our session schema, then evaluated on 22 npm sessions captured by our monitor
(16 benign, 6 malicious).

| Model | Accuracy on npm | Benign recall | Malicious recall |
|---|---|---|---|
| Random Forest | 72.73% | 100% (16/16) | **0% (0/6)** |
| XGBoost | 72.73% | 100% (16/16) | **0% (0/6)** |

The 72.73% accuracy is an artefact of class imbalance. Both models predicted "benign"
for every input. Neither detected a single malicious package.

---

## Evidence line 1: the model's ranking is inverted, not merely mis-thresholded

Malicious-class confidence scores from the Random Forest:

| Group | Scores | Mean |
|---|---|---|
| Benign npm (n=16) | 48.6, 32.2, 47.7, 48.6, 47.9, 48.6, 49.6, 38.0, 38.0, 34.2, 33.2, 34.1, 35.0, 33.1, 34.1, 33.1 | **39.1%** |
| Malicious npm (n=6) | 37.9, 29.2, 30.8, 23.2, 30.0, 29.9 | **30.2%** |

The model scored benign packages as *more* malicious than actual malware. `lodash`
received 48.6% while `reverse-shell-test` received 23.2%. Only 8 of 96 benign/malicious
pairs are ranked correctly, giving an approximate **ROC AUC of 0.08** against a
random-guessing baseline of 0.50.

This rules out an entire family of remedies. Threshold tuning, `class_weight='balanced'`,
and probability calibration all preserve the ranking; none can repair a ranking that is
inverted. Lowering the decision threshold would flag `lodash` before `ssh-reader-test`.

## Evidence line 2: nine features point in opposite directions across domains

Measured by Cohen's d within each domain independently. Positive d means the malicious
class scores higher.

| Feature | d (npm) | d (QUT) | Status |
|---|---|---|---|
| `sc_network_ops` | **+1.55** | **-1.18** | CONFLICT |
| `pat_error_handle` | +1.99 | -0.37 | CONFLICT |
| `tcp_remote_ports` | +1.49 | -0.53 | CONFLICT |
| `sc_process_ops` | +1.32 | -0.33 | CONFLICT |
| `os_home_dir` | -0.40 | +1.02 | CONFLICT |
| `tcp_local_ports` | +0.90 | -0.35 | CONFLICT |
| `tcp_state_transitions` | +0.70 | -0.42 | CONFLICT |
| `sc_file_ops` | +0.45 | -0.29 | CONFLICT |
| `tcp_remote_ips` | +0.36 | -0.37 | CONFLICT |

Nine features conflict, six agree, and the remaining twenty-two are too weak in at
least one domain to matter. The conflicts include the strongest available signals.

`sc_network_ops` is the clearest case: a large effect in *both* domains (|d| > 1.1
each) with opposite signs. The model learned "high network activity indicates benign"
and applied that rule to npm, where high network activity indicates the opposite.

## Evidence line 3: QUT's malicious class is defined backwards from ours

Total syscall volume in QUT-DV25, by label:

| QUT class | Median syscalls | Mean |
|---|---|---|
| Benign (n=7,144) | 10,415 | 42,386 |
| Malicious (n=7,127) | 5,171 | 10,615 |

QUT's malicious packages perform roughly **half** the work of its benign packages.
This is consistent with what those samples are: the malicious set is dominated by
typosquat and dependency-confusion packages (`10Cent10-999.0.4.tar.gz`,
`11Cent-999.0.0.tar.gz` — the `999.0.x` version marker is characteristic), which
exfiltrate a small payload and exit. QUT's benign set consists of real libraries
resolving full dependency trees, which is far more activity.

In QUT, "malicious" correlates with **low activity**.

Our npm malware is structurally the opposite: a complete, normal `npm install` *plus*
attack behaviour added through a `postinstall` hook. Added behaviour only increases
syscall volume; it never decreases it.

In our data, "malicious" correlates with **high activity**.

Every activity-volume feature therefore transfers with the wrong sign. This is not a
Python-versus-JavaScript problem. It is a difference in how the two datasets constitute
their malicious class.

## Evidence line 4: feature selection cannot repair it

`diagnose_features.py` applies four successive filters to all 37 features:

```
37 features
 -> 13  scales comparable across domains (median ratio < 10x)
 -> 12  ...also separate classes in npm (|d| >= 0.2)
 ->  6  ...also separate classes in QUT (|d| >= 0.2)
 ->  2  ...also point the same direction in both
```

The two survivors do not hold up under inspection:

- `os_user_dir` (d_npm = +2.70) is a capture artefact. Every benign session reads
  exactly 865 or 879; every malicious session reads 904-913. The near-zero variance
  inflates d from a ~3% difference. It tracks the synthetic test-package template,
  not malice.
- `sc_io_ops` has |d| ~ 0.25 in both domains, which is barely above noise.

**Effectively zero trustworthy transferable features.**

## Evidence line 5: the domain gap is methodological, not ecological

See [`OOD_ANALYSIS_REPORT.md`](OOD_ANALYSIS_REPORT.md) (August 29, 2026) for the full
analysis. Summary: capturing *PyPI* packages with *our* monitor — holding ecosystem
constant against QUT — did not reduce the distance to QUT's training manifold. It
increased it by approximately 51x.

| Source | Mean NN distance to QUT | Std above QUT median |
|---|---|---|
| Our PyPI captures (n=3) | 524.89 | 505 sigma |
| Our npm captures (n=24) | 10.28 | 9 sigma |
| QUT internal | 0.92 (median) | 0 by definition |

This rejects the ecosystem hypothesis. The gap is caused by differing eBPF
implementations and feature-extraction methodologies, not by PyPI versus npm.

**Caveat for the writeup:** the PyPI arm is only 3 samples, captured with tooling
that is not present in this repository (the Go monitor has no pip detector). The
specific 51x figure should be treated as indicative rather than precise. Its
directional conclusion is independently corroborated by evidence lines 2 and 3,
so the conclusion survives even if that number does not.

## Evidence line 6: the pattern features were never comparable

`p1_file_metadata` was identified in the OOD report as the single largest contributor
to the PyPI distance (2,559-2,569 in our PyPI captures versus a QUT 99th percentile
around 5). The cause is now understood.

Our implementation counts one exact consecutive syscall triplet:

```go
// internal/features/ngram_counter.go
pattern1FileMetadata = []uint32{262, 257, 5}   // newfstatat -> openat -> fstat
```

That sequence is precisely what CPython's import machinery executes for every module
lookup while walking `sys.path`. `p1_file_metadata` is therefore, in effect, a
Python-runtime detector rather than a malware feature. Node.js resolves modules
differently, which is why npm sessions read 2-15.

Separately, QUT's `Pattern_1` column is not a count at all. It holds a string naming
the most frequent 3-gram, for example `"newfstatat -> newfstatat -> newfstatat"`.
The mapping in `train_on_qut.py` forced the two together by counting substring
occurrences in QUT's text columns, producing values with no shared meaning.

All ten pattern features were incomparable by construction.

---

## Consequences

**The 36-feature schema constraint is lifted.** `internal/features/dir_counter.go`
currently collapses `.ssh`, `.aws`, `.kube` and wallet paths into `other_dir_access`
specifically to hold the feature count at 36 for QUT compatibility, and
`dir_counter_test.go` enforces that omission. `internal/features/pathclass.go` already
performs the classification; the signal exists and is discarded. This is why
`ssh-reader-test` produced a feature vector containing no indication that an SSH key
was read. The schema can now be designed for npm detection rather than QUT parity.

**Verdict-engine output becomes usable as ML features.** Previously this would have
been circular, since `assign_label` in `feature_analysis.py` derives labels from
`verdict_level`. Once labels come from an external ground-truth corpus, verdict
findings are legitimate inputs. Audit finding NC1 (`EXFIL-001` false-positive banding
on an ordinary install) should be fixed before that rule is trusted as a feature.

**Evaluation is currently impossible.** The malicious class is 6 synthetic packages
built from one template. Any feature distinguishing that template from real libraries
reads as a malware signal, which the `os_user_dir` artefact demonstrates. Real
malicious samples are needed for the test set before any accuracy claim is meaningful.

---

## What this contributes to the report

This is a negative result with a measured mechanism, which is considerably stronger
than an unexplained low score. The claim that can be defended:

> Cross-ecosystem transfer from PyPI (QUT-DV25) to npm failed because the source
> dataset's malicious class is characterised by *reduced* process activity while the
> target's is characterised by *increased* activity, producing directional conflict in
> 9 of 37 features and a below-chance ROC AUC of 0.08. The failure is not attributable
> to ecosystem difference: holding ecosystem constant by capturing PyPI with the same
> monitor increased rather than decreased distributional distance, isolating the cause
> as methodological incompatibility between eBPF collection implementations.

---

## Reproducing these results

```bash
cd ml_analysis
python train_on_qut.py        # the failed transfer, 0% malicious recall
python diagnose_features.py   # the four-filter funnel and direction analysis
```

| Artefact | Contents |
|---|---|
| `outputs/qut_trained_npm_predictions.csv` | Per-package predictions and confidences |
| `outputs/feature_diagnostics.csv` | Per-feature verdicts, both-domain effect sizes, scale ratios |
| `OOD_ANALYSIS_REPORT.md` | Nearest-neighbour distance analysis |

---

## Superseded

| File | Status |
|---|---|
| `train_on_qut.py` | Superseded. Retained as evidence; do not extend. |
| `outputs/qut_trained_npm_predictions.csv` | Historical record of the failed run. |

`diagnose_features.py` remains useful — the per-domain effect size and dead-feature
checks apply to any future dataset and should be re-run against the npm corpus once
it exists.
