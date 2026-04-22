# Phase-2 Review: Step-by-Step Implementation Guide

## Step 0: What this project does (one-line)
Classifies a Python package installation behavior as **Benign (0)** or **Malicious (1)** using the QUT-DV25 behavioral trace dataset and a Hybrid XGBoost + LSTM model.

---

## Step 1: Dataset note (QUT-DV25)
- Dataset used: QUT-DV25 dynamic behavior traces.
- Samples in this project run: 200 total
  - 100 benign
  - 100 malicious
- Split used by current pipeline:
  - Train: 140
  - Validation: 30
  - Test: 30
- Important review note: this is a balanced but small benchmark; results are strong for prototype validation, and future work should add more recent real-world samples.

---

## Step 2: Where raw traces come from (layman)
When a package is installed in a monitored Linux environment, low-level events are captured, such as:
- file operations
- process/syscall activity
- network/TCP behavior

In practice, tools like filetop, opensnoop, tcpstates, and strace generate trace logs. Your code then reads those logs from disk.

---

## Step 3: Trace parsing (code stage)
The parser merges multiple trace files for each package into one structured record:
- File discovery and package matching
- Parse each trace type
- Build one unified package-level event object
- Save parsed JSON files

Primary implementation files:
- src/preprocessing/parse_traces.py
- src/preprocessing/trace_parsers.py

Outputs produced:
- data/processed/benign_parsed.json
- data/processed/malicious_parsed.json
- data/splits/train.json, val.json, test.json

---

## Step 4: Feature extraction (how traces become ML input)
The project transforms raw parsed events into **36 fixed numeric QUT features**:

Feature groups:
1. Filetop features (5)
2. Installation/dependency features (3)
3. Opensnoop directory-access features (7)
4. TCP/network features (5)
5. Syscall category counts (6)
6. Pattern intensity features (10)

Primary implementation file:
- src/features/qut_feature_extractor.py

Why this step matters:
- ML models cannot directly use raw text traces.
- Feature extraction converts complex logs into a consistent numeric vector per package.

---

## Step 5: Hybrid model architecture
Stage A: Train XGBoost on the 36 features.
- Output: class probabilities + leaf indices.

Stage B: Enrich features.
- 36 original + 2 probabilities + 10 leaf-index features = 48 features.

Stage C: Train LSTM with attention on the 48-feature sequence.
- Output: final benign/malicious prediction.

Primary implementation file:
- train_hybrid_model.py

---

## Step 6: How to run once (exact command)
From the project root:

C:/Users/ksj42/AppData/Local/Microsoft/WindowsApps/python3.13.exe train_hybrid_model.py

This performs:
- load pre-extracted QUT features
- train hybrid model
- evaluate on test split
- save artifacts to trained_models/hybrid_model/

---

## Step 7: Latest run results (executed on 2026-03-24)
From trained_models/hybrid_model/hybrid_results.json:

Hybrid XGBoost+LSTM (Test set, n=30)
- Accuracy: 96.67%
- Precision: 1.0000
- Recall: 0.9333
- F1-score: 0.9655
- AUC-ROC: 0.9333

XGBoost standalone (same split)
- Accuracy: 96.67%
- Precision: 1.0000
- Recall: 0.9333
- F1-score: 0.9655
- AUC-ROC: 0.9556

Confusion matrix (Hybrid)
- TN: 15
- FP: 0
- FN: 1
- TP: 14

Interpretation for review:
- Zero false positives on this test split.
- One false negative out of 30 total test samples.
- Strong precision for security screening scenarios.

---

## Step 8: What to say if reviewer asks “Is ML needed and feasible?”
**Needed:**
- Rule-based signatures miss new or obfuscated malware behavior.
- Behavioral ML can combine many weak signals (files + network + syscalls) into one decision.

**Feasible:**
- Data pipeline is already automated (parse → feature extraction → train/evaluate).
- Training runs on CPU in this setup.
- Clear reproducible artifacts and metrics are generated.

---

## Step 9: Layman explanation of eBPF trace flow (short speech form)
“Think of package installation like observing a person in a room. We do not just read what they claim; we watch what they actually do. Traces are those observations: which files were opened, which network connections were made, and what system calls were executed. We summarize these observations into 36 behavior scores, then pass those scores into our Hybrid model. XGBoost gives a strong first opinion, then LSTM analyzes the enriched pattern for a final verdict: benign or malicious.”

---

## Step 10: Detailed presentation speech (Data Preprocessing + Feature Extraction)
Use this as your speaking script:

“Now I will explain the preprocessing and feature engineering pipeline in detail.

First, we start with raw behavior traces captured during package installation. These traces come from monitoring tools and include file events, open syscalls, TCP state changes, installation logs, and detailed syscall traces.

Second, we parse these heterogeneous files into a unified structure per package. Instead of keeping them as separate text logs, we normalize them into structured JSON objects with common fields, such as process name, operation type, paths, ports, and syscall counts.

Third, we create train, validation, and test splits while preserving class balance between benign and malicious packages.

Fourth, we perform feature extraction. This is the key bridge between raw traces and machine learning. We convert each package’s behavior into 36 numeric QUT features grouped into six categories.

In the filetop category, we quantify read and write process behavior and data transfer volumes.
In installation features, we quantify dependency characteristics.
In opensnoop features, we quantify access patterns to sensitive directory groups.
In TCP features, we quantify connection-state activity and local/remote endpoint diversity.
In syscall-category features, we aggregate low-level call frequencies into interpretable groups such as file, network, process, and security operations.
In pattern features, we score known behavioral motifs like repeated write chains, process creation chains, socket behavior, and error-heavy execution traces.

Fifth, these 36 features are standardized and sent into XGBoost. XGBoost outputs class probabilities and leaf-index decision-path signals. We concatenate those with original features to create a 48-dimensional enriched representation.

Finally, this enriched sequence is fed into an attention-based LSTM. The LSTM learns higher-order interactions and produces the final malicious probability.

So in summary, preprocessing converts noisy system traces into clean, structured, and reproducible behavioral vectors. Feature extraction translates low-level kernel-level activity into model-ready signals. This is what makes reliable classification possible.”

---

## Step 11: Reviewer caution note (important)
When presenting metrics, clearly mention:
- benchmark dataset size is limited
- results are from the current fixed split
- next phase should validate on additional unseen and newer malware samples

This strengthens credibility and demonstrates research maturity.
