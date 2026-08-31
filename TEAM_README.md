# Project Guide for the Team — Read This First

**Project:** Identifying Prompt Injections in CLI Tools During Package
Installation using eBPF and ML
**Project ID:** PW26_PB04 | **Guide:** Prof. Priya Badrinath
**Team:** Aniruddha (CS076), Manikandan (CS277), Karthik (CS285), Komal (CS308)

This document assumes you know nothing about the project. Read it top to
bottom once and you will be able to explain the whole thing to the panel.

> Looking for build/run instructions instead? See [`README.md`](README.md).
>
> **Manikandan and Komal:** your slide assignments are in
> [section 12](#12-who-does-what-for-the-phase-3-deck) at the bottom. Read
> sections 1–6 first, then jump there — section 12 tells you which parts you
> personally need to know in depth.

---

## 1. The problem in one paragraph

When a developer types `npm install some-package`, that command is allowed to
run arbitrary code on their laptop automatically, before the developer has
even looked at the package. This is a feature (packages need to set
themselves up) but attackers abuse it. Our specific angle: attackers are now
writing packages that, during install, go looking for the AI coding
assistants developers have on their machines (Claude, Copilot, Cursor) and
feed them malicious instructions — "prompt injection" — to make the trusted
AI tool do the dirty work: read SSH keys, read `.env` files, phone home.

Nobody catches this well today. Antivirus doesn't look at npm. Static code
scanners get defeated by obfuscation. Reputation systems can't help with a
brand-new package.

---

## 2. Our solution in one paragraph

We watch the installation from **inside the Linux kernel** using a technology
called **eBPF**, so the malicious code cannot hide from us or turn us off. We
record everything it does — every file opened, every network connection,
every system call — turn that recording into a row of numbers, and feed that
row to a **machine learning model** that decides "benign" or "malicious".

---

## 3. Vocabulary you must know (plain English)

| Term | What it actually means |
|---|---|
| **npm** | The app store for JavaScript code. `npm install x` downloads and sets up package x. |
| **PyPI / pip** | Same thing, but for Python. `pip install x`. |
| **Post-install script** | Code a package is allowed to run automatically right after download. This is the attack door. |
| **Syscall** | Any time a program wants to do something real (open a file, send data), it must ask the kernel. That request is a syscall. |
| **Kernel** | The core of the operating system. Every program must go through it. It sees everything. |
| **eBPF** | A safe way to run tiny observer programs *inside* the kernel. Near-zero slowdown, cannot be bypassed from userspace. This is our superpower. |
| **Probe** | One eBPF observer watching one specific thing (e.g. "tell me every file that gets opened"). |
| **Ring buffer** | A shared memory pipe that carries observations from kernel to our program without copying. Fast. |
| **Go daemon** | Our program that sits in userspace, drinks from the ring buffer, and tallies everything up. |
| **Session** | One complete `npm install` from start to finish. One session = one row of data. |
| **Feature** | One number describing the session. E.g. "how many times it touched /etc". |
| **Feature vector** | The full row of 36 numbers describing one session. |
| **QUT-DV25** | A public research dataset from Queensland University of Technology. 14,271 Python packages (about half malicious) that somebody else already recorded and labelled. We train our model on it because we don't have 14,000 samples of our own. |
| **Label** | The correct answer. 0 = benign, 1 = malicious. |
| **Recall** | Of all the genuinely malicious packages, what percentage did we catch? This is the number that matters most for security. |
| **In-distribution / Out-of-distribution (OOD)** | Does new data "look like" the data the model was trained on? If not, the model's predictions are meaningless. |
| **Domain shift** | When your test data systematically differs from your training data. Models break. |
| **n-gram** | A short sequence. A syscall 3-gram is three syscalls in a row, e.g. `read -> read -> close`. Repeating patterns are behavioural fingerprints. |

---

## 4. The pipeline, layer by layer

This is the part you will be asked to explain. There are six layers.

    LAYER 1  Kernel  — 4 eBPF probes watching the install
                |
    LAYER 2  Ring buffers — zero-copy pipe, kernel to userspace
                |
    LAYER 3  Go collectors — 5 goroutines reading the pipe
                |
    LAYER 4  Router + Session — sorts events into the right install session
                |
    LAYER 5  Aggregators — turn raw events into 36 numbers
                |
    LAYER 6  Output — JSON file + CSV row -> ML model -> verdict

### Layer 1 — The four eBPF probes

| Probe | Watches | Why we need it |
|---|---|---|
| **Process Tracer** | Programs starting and stopping | npm spawns dozens of child processes. We must follow all of them, including any AI CLI tool it launches. |
| **Syscall Tracer** | Every system call | Gives us the behavioural fingerprint (the n-grams). |
| **File Monitor** | Every file open | Catches access to `~/.ssh/id_rsa`, `.env`, `/etc/shadow`. |
| **TCP Monitor** | Network connections | Catches data being sent out (exfiltration). |

All four share one lookup table called `tracked_pids`. The Process Tracer
puts the npm process in it, and every child gets added automatically. The
other three probes check this table before recording anything — that's how we
only record *our* install and not the rest of your computer.

### Layer 5 — The 36 features (grouped)

| Group | Count | Examples |
|---|---|---|
| Filetop | 5 | how many processes read/wrote, how many KB |
| Install | 3 | number of dependencies |
| Directory access | 7 | accesses to /root, /tmp, /home, /etc, ... |
| Network (TCP) | 5 | connection state changes, unique remote IPs/ports |
| Syscall categories | 6 | file ops, network ops, IO ops, security ops, ... |
| N-gram patterns | 10 | the 10 most frequent syscall 3-grams |

36 features + `package_name` + `label` + `severity_score` = **39 columns**
in our exported CSV.

### Layer 6 — Two things decide "malicious"

1. **Verdict engine** (rule-based, added this phase). 12 handwritten rules,
   each tagged with a MITRE ATT&CK technique. Two are *decisive* — if they
   fire, the session is malicious no matter what the score is:
   - `PERSIST-001` — wrote into a startup/cron location (it wants to survive reboot)
   - `EXFIL-001` — read something sensitive, *then* opened a network connection

   This is fast, explainable, and needs no ML.
2. **ML model** (Random Forest / XGBoost). Trained on QUT-DV25, gives a
   probability. This is the part with the open problem — see section 6.

---

## 5. What we built in Phase 2 (already submitted)

- All four eBPF probes working, CO-RE portable across kernel versions
- Go daemon with the full session pipeline
- 36-feature JSON + CSV export matching QUT-DV25's schema
- Hybrid XGBoost + LSTM model
- Measured performance: **under 4% CPU overhead, zero dropped events**
- **Reported result: 96.67% accuracy on the QUT test set, and we claimed
  "perfect recall" on our own eBPF sessions.**

That last claim turned out to be wrong. Finding that out is most of Phase 3.

---

## 6. What happened in Phase 3 (the investigation)

This is the interesting part and the strongest thing we have to present.
It reads like a detective story, so learn it as one.

**Step 1 — The alarm.** We re-ran the model properly on 24 real npm captures.
Result: it classified every single benign package correctly, and **caught 0
out of 6 malicious packages. 0% recall.** The Phase 2 "perfect recall" claim
came from a tiny 10-session balanced pool and did not survive a bigger test.

**Step 2 — First theory: wrong ecosystem.** QUT-DV25 is Python/PyPI data. We
were testing on JavaScript/npm. Maybe the model simply can't read npm.
Aniruddha rewrote the monitor to also support `pip install` and captured 3
PyPI packages, so we could test the theory.

**Step 3 — The distance test.** Rather than measure accuracy on 3 samples
(meaningless), we asked a better question: *do these rows even look like
QUT-DV25's data?* We measured how far each of our rows sat from its nearest
QUT-DV25 neighbour, and compared that to how far QUT-DV25's own rows sit from
each other. Result: our PyPI rows were **505 standard deviations** away.
Absurd. That's not domain shift, that's a bug.

**Step 4 — The bug.** Two of them, actually.

- The handoff document had an **off-by-one column mapping error** — it listed
  a column (`unknown_ops`) that the exporter never actually writes, so
  columns 29–39 were all shifted by one. Anyone building a feature map from
  that table was silently mapping the wrong data.
- Worse: QUT-DV25's `Pattern_1..10` columns are **not counts**. They are the
  *identity* of the most frequent 3-gram — a text string like
  `newfstatat -> newfstatat -> newfstatat`. Our code was counting keyword
  occurrences and getting ~2,560, then comparing that against QUT's strings
  converted to category codes 0–5. **We were comparing a count to a category
  label.** The 505σ was real arithmetic on meaningless inputs.

**Step 5 — Sanity check the pipeline.** Before trusting anything, we checked
whether our own ML code could reproduce the QUT-DV25 paper's published
result. Paper says 95.99% accuracy / 96.02% F1. **We got 97.30% / 97.27%.**
Our pipeline is sound. Good — the bug is in the data mapping, not the model.

**Step 6 — The fix.** QUT publishes raw trace files for 200 of its packages.
Aniruddha recomputed the real 3-gram *counts* from those raw files using the
exact same algorithm our monitor uses, producing a 196-package reference set.
Now we could compare count against count — apples to apples.

**Step 7 — The clean answer.** With the correct comparison:

- PyPI rows sit at the **73.5th percentile** of QUT-DV25's own spread
- npm rows sit at the **78.3rd percentile**
- Anything under the 95th percentile counts as in-distribution

**Both ecosystems are IN-DISTRIBUTION.** The data was never alien. The 0%
recall was never a domain-shift problem. It was an encoding bug.

**Step 8 — But recall is still 0%.** We retrained on the corrected reference
set (93.4% cross-validation accuracy) and tested on our captures. Still 0
out of 7 malicious caught. So we looked at *why*:

| | Benign `p1_count` | Malicious `p1_count` |
|---|---|---|
| **QUT-DV25** | median 3,235 | median **1,678** |
| **Our captures** | median 2,824 | median **2,812** |

In QUT-DV25, real malware does *less* work than benign packages — it skips
the real installation and just steals and exits. The model correctly learned
"low activity = malicious."

Our malicious test packages are **hand-written fixtures that do a full,
normal installation and then also do something bad**. So their activity level
is identical to benign. The model isn't broken — it's answering a question
about a different kind of malware than the kind we built.

**This is called the provenance gap:** QUT has 7,127 *real* malicious
packages collected from the wild; we have 7 *synthetic* ones we wrote
ourselves, because you cannot safely install real malware on a capture
machine.

---

## 7. What Phase 3 actually delivers

1. A working **PyPI/pip capture path** alongside npm (the monitor is no
   longer npm-only)
2. **Schema 2.0.0** — 44 columns, now exporting both the winning n-gram
   *and* its count, so no future consumer has to guess
3. A **corrected feature contract** — the off-by-one column bug is fixed and
   the table is now generated from the exporter's real header
4. A **rebuilt QUT reference set** (196 packages with true frequency counts,
   reconstructed from raw traces)
5. **Reproduction of the published benchmark** at 97.30% — proof our pipeline
   is correct
6. A rigorous **out-of-distribution study** proving both ecosystems are
   in-distribution, and an honest correction of Phase 2's recall claim
7. The **verdict engine** — 12 explainable MITRE-tagged rules that catch our
   malicious fixtures *today*, without any ML

Point 7 matters: **the rule engine works even though the ML doesn't yet.**
Our malicious fixtures do get flagged, by the rules.

---

## 8. What is still open (say this honestly if asked)

- **ML recall on our fixtures is 0%**, and we know exactly why (provenance
  gap, section 6 step 8). Not a mystery, a documented limitation.
- ~17 of the 36 features are measured differently by QUT (system-wide) than
  by us (process-scoped). Deliberate — matching them would mean polluting our
  captures with unrelated desktop noise.
- Our benign PyPI arm is one synthetic fixture; the npm side has 8 real
  registry packages.
- Next real step: either collect a much larger corpus of our own, or source
  real malicious samples so the training data matches our threat model.

---

## 9. The 60-second version (memorise this)

> Package managers run code automatically at install time, and attackers use
> that to hijack the AI coding tools developers have installed. We watch the
> install from inside the Linux kernel with eBPF, which malware can't evade,
> and turn each install into 36 behavioural numbers. Those go to a rule engine
> and an ML classifier.
>
> In Phase 3 we added PyPI support, and we investigated why our model scored
> 0% recall. We found it was a feature-encoding bug, not a domain-shift
> problem — we proved that by reproducing the source paper's benchmark at
> 97.3% and by showing both ecosystems are statistically in-distribution once
> the encoding is fixed. The remaining recall gap is a provenance gap: the
> public dataset's malware is real and does minimal work, ours is synthetic
> and does a full install. Our rule engine catches them regardless.

---

## 10. Phase 2 → Phase 3 change table

This is what the panel will actually grade.

| Area | Phase 2 (submitted) | Phase 3 (now) |
|---|---|---|
| Ecosystems | npm only | npm **and** PyPI/pip |
| Schema | 39 columns, v1.0.0 | **44 columns, v2.0.0** — exports `pN_ngram` *and* `pN_count` |
| Feature contract | Off-by-one error; listed `unknown_ops` as col 29, shifting cols 29–39 | **Fixed**, table generated from the exporter's real header |
| Decision layer | ML only | ML **+ 12-rule verdict engine** with MITRE tags, 2 decisive rules |
| Evidence | Directory *counts* only | **Path classification** (13 classes) + argv classification (5 classes) + first-seen timestamps, enabling ordering rules |
| Claimed recall | "Perfect recall for the malicious class" | **Corrected to 0%** on a larger 24-sample test — with root cause identified |
| Benchmark validation | Not done independently | **Reproduced the QUT paper at 97.30% vs their 95.99%** |
| OOD analysis | None | Full nearest-neighbour + percentile study; both ecosystems in-distribution |
| Ground truth | 6 synthetic fixtures | + 8 real npm registry packages (lodash, express, chalk, debug, axios, moment, uuid, dotenv) |
| Known bugs closed | C1–C4, H1–H3, H5 | + `FileEvent` struct padding bug (corrupted every timestamp), session double-completion race, silent event drops now counted |

**Important framing:** Phase 2's abstract claims "perfect recall for the
malicious class." Phase 3 contradicts that. Do **not** hide it — lead with it.
"We stress-tested our own Phase 2 result, found it didn't hold at larger
sample size, and spent Phase 3 finding out exactly why" is a much stronger
story than a number nobody checked.

---

## 11. Where the evidence lives

| What | Path |
|---|---|
| Benchmark reproduction result | `ml_analysis/outputs/qut_benchmark_results.csv` |
| OOD comparison (schema 2.0.0) | `ml_analysis/outputs/ood_comparison_schema2.csv` |
| Count-vs-count NN distances | `ml_analysis/outputs/pypi_nn_count_vs_count.csv`, `npm_nn_count_vs_count.csv` |
| Predictions after corrected alignment | `ml_analysis/outputs/corrected_alignment_predictions.csv` |
| Full OOD write-up | `ml_analysis/OOD_ANALYSIS_REPORT.md` |
| Architecture changes this phase | `docs/ARCHITECTURE_CHANGES.md` |
| Open findings / audit | `docs/NEW_AUDIT.md` |
| PyPI rewrite step-by-step | `docs/pypi-rewrite/` (on branch `feat/pypi-rewrite`) |
| Feature column contract | `docs/ml_handoff.md` |

---

## 12. Who does what for the Phase 3 deck

> **Assumption:** this maps to the standard PES ESA slide structure. If the
> Phase 3 template mandates a different slide list, keep the *ownership split*
> below and just remap the slide numbers.

### Reading guide — do this before you start

| Person | Must read in depth | Can skim |
|---|---|---|
| **Manikandan** | Sections 1, 2, 3, 4, 5 | 6, 7, 8 |
| **Komal** | Sections 6, 7, 8, 10, 11 | 1, 2, 3 |

Both of you must read **section 6**. It is the longest section and the most
tempting to skip. If you skip it you will present a contradiction to the
panel without realising it, because section 5 ends on a claim that section 6
overturns.

---

### Manikandan — Narrative & context (slides 1–10)

You own everything up to the architecture. You do **not** need to understand
the ML investigation to do your part.

| # | Deliverable | Where the material is |
|---|---|---|
| 1 | Title / team / guide slide | Phase 2 dissertation p.1 — copy it, update "Phase 2" to "Phase 3" |
| 2 | Problem Statement (2 slides) | Section 1 of this doc. Phase 2's framing was good — reuse it |
| 3 | Motivation — real incidents | Phase 2 §2.3: event-stream (2018), ua-parser-js (2021), nx compromise. Add one 2026 incident if you can find a credible source |
| 4 | Literature Survey refresh | Phase 2 Ch.2 already has 8 papers. **Your one new contribution:** add a critique slide on QUT-DV25's methodology — that their `Pattern_N` columns are frequency *ranks* (which 3-gram won), not semantic categories as the appendix table implies, and that their published CSV omits the counts their paper says they trained on. We found this ourselves. It is a genuine, citable finding |
| 5 | Objectives — Phase 3 specific | Derive from section 7 of this doc |
| 6 | Phase 2 recap (1 slide, move fast) | Section 5 of this doc |
| 7 | Architecture recap | Reuse Phase 2 Figures 1–4 unchanged |

**Estimated effort: ~6 hours.**

**Watch out for:** on slide 6, state the Phase 2 recall claim as *"what we
reported in Phase 2"* — not as a current fact. Komal's slides immediately
after yours will correct it. If you assert it as still true, the deck
contradicts itself.

---

### Komal — Results, figures & formatting (slides 11–22)

You own the results half and the overall look of the deck. Your slides carry
the Phase 3 story, so section 6 of this doc is your script.

| # | Deliverable | Where the material is |
|---|---|---|
| 1 | Updated architecture diagram | Phase 2 Fig 1, plus one new box for the verdict engine after the aggregation layer. Exact flow is in `docs/ARCHITECTURE_CHANGES.md` §5 |
| 2 | **Phase 2 → Phase 3 comparison table** | Section 10 of this doc. This is the single most important slide in the deck — the panel is grading delta |
| 3 | Benchmark reproduction | `ml_analysis/outputs/qut_benchmark_results.csv`. Two-row table: Paper 95.99% / 96.02% vs Ours 97.30% / 97.27% |
| 4 | The investigation (3 slides) | Section 6, steps 1→8. One slide per act: **the alarm** (steps 1–2), **the bug** (steps 3–4), **the clean answer** (steps 5–7) |
| 5 | OOD result | `ml_analysis/outputs/ood_comparison_schema2.csv` plus the count-vs-count figures: PyPI 73.5th percentile, npm 78.3rd, threshold 95th |
| 6 | The provenance gap | Section 6 step 8 — reproduce that four-cell median table as-is. It explains the 0% recall in one visual, better than any paragraph |
| 7 | Verdict engine | 12 rules, 2 decisive, MITRE-tagged. `docs/ARCHITECTURE_CHANGES.md` §5 |
| 8 | Performance | Reuse Phase 2 §6.2 unchanged — under 4% CPU, zero dropped events |
| 9 | Limitations & Future Work | Section 8 of this doc |
| 10 | References | Phase 2 Ch.8 as-is. Add entries only if Manikandan sources a new paper |
| 11 | Whole-deck formatting pass | Fonts, figure captions, slide numbers, consistent table styling |

**Estimated effort: ~10 hours.**

**Watch out for:** slide 4 is a story, not a data dump. Deliver it in that
order — *we found a problem, we found the cause, we proved the cause*. If you
lead with the 505σ number without the setup, it reads as a failure rather
than as the diagnostic win it actually was.

---

### Karthik — retained (not delegated)

- ML methodology — expect the hard questions here
- Live demo, if there is a slot
- Q&A defence on why 0% recall is a *finding* and not a failure

### Aniruddha — already covered

The `docs/pypi-rewrite/` step documents are the implementation evidence for
the PyPI work. No additional slide-writing needed from him.

---

### Suggested two-day schedule

| When | Manikandan | Komal |
|---|---|---|
| **Day 1 morning** | Read sections 1–6 | Read sections 6–11 |
| **Day 1 afternoon** | Slides 1–5 drafted | Slides 1–4 drafted (arch diagram + comparison table first) |
| **Day 1 evening** | Send drafts to Karthik for a factual check | Same |
| **Day 2 morning** | Slides 6–7, incorporate feedback | Slides 5–9, incorporate feedback |
| **Day 2 afternoon** | Hand deck to Komal | Merge both halves, formatting pass |
| **Day 2 evening** | Full team dry run, both must be able to deliver section 9 from memory | Same |

**Hard rule for the dry run:** each person must be able to explain their own
slides *without* reading them, and must be able to answer "what changed since
Phase 2" using section 10. If either of you can't do that, the split has
failed and we redistribute.
