# eBPF-Based Malware Detection with a Hybrid ML Model

This repository connects **real npm install monitoring** (eBPF session JSON from your teammate’s exporter) with a **hybrid machine learning model** (XGBoost plus LSTM) trained on **QUT-DV25–style features**: 36 numeric signals that summarize file, install, directory, TCP, syscall, and pattern behavior.

The sections below explain **what data you use**, **how it is turned into numbers**, **how it flows through the hybrid model**, and **what results we measured** on the QUT held-out test set and on a **balanced eBPF validation pool**.

---

## 1. Project overview (plain language)

- **Goal:** Decide whether an `npm install` session looks **benign** or **malicious** using traces collected in the kernel (eBPF) and summarized as JSON.
- **Academic backbone:** The **QUT-DV25** dataset gives you many labeled examples of benign vs typosquatting / malicious PyPI-style packages, already converted into long trace records.
- **Real-world hook:** Your **eBPF session files** are shorter JSON summaries of one install each. The same **36-feature layout** is used so one model family can be trained on QUT and checked on eBPF exports.
- **Model:** A **hybrid** stack: **XGBoost** learns strong tabular patterns on the 36 features; an **LSTM** sits on top of XGBoost outputs plus scaled features to refine the decision.

---

## 2. Datasets we use

### 2.1 QUT-DV25 (training backbone)

| Item | Detail |
|------|--------|
| **What it is** | A research dataset of benign vs malicious Python package installs with multiple trace modalities (filetop, opensnoop, TCP, syscalls, etc.). |
| **How we store it** | Raw text traces under `data/raw/` (benign / malicious folder layout). Parsed traces live in large JSON lists: `data/processed/benign_parsed.json` and `data/processed/malicious_parsed.json`. |
| **Sample count** | **100 benign** and **100 malicious** parsed packages (200 total) in the current pipeline configuration. |
| **What we extract** | Exactly **36 features** aligned with the QUT-DV25 feature set (names in `src/features/qut_feature_extractor.py` as `QUT_FEATURE_NAMES`). |

**Why QUT matters:** It gives a **labeled**, reasonably sized set to train the hybrid model where “malicious” is not rare. That stabilizes training compared to only a handful of eBPF JSONs.

### 2.2 eBPF session JSON (real installs)

| Item | Detail |
|------|--------|
| **What it is** | One JSON file per monitored `npm install`, produced by the Go/npm eBPF monitor (e.g. under `capstone-main(aniruddha_imp)/capstone-main/sessions/`). |
| **Sibling drop folder** | `capstone_ebpf_repo` on the **Desktop** (next to this project folder) holds additional labeled exports you add over time. |
| **Labels** | Prefer an integer field `"label": 0` (benign) or `1` (malicious). If `label` is missing, `scripts/import_sessions_to_qut.py` and `scripts/validate_sessions_with_qut.py` use **`derive_label()`** (filename / package name heuristics plus benign-test / lodash rules). |

**Important detail (preprocessing fix):** Some older JSON used **PascalCase** TCP keys (`StateTransitions`, …). The importer also accepts **snake_case** (`state_transitions`, …) so TCP counts are not read as zeros by mistake.

---

## 3. How data is preprocessed (end-to-end)

Think of **three parallel paths**: (A) QUT to numpy tables, (B) eBPF JSON to the same 36 columns, (C) optional blend for training.

### Path A — QUT features on disk (no 18 GB RAM spike)

1. **Raw traces** live under `data/raw/…`.
2. **Parsing** (when you run the legacy parse step) fills `data/processed/*_parsed.json`.
3. **`scripts/regenerate_qut_features_streaming.py`** reads those JSON arrays **one sample at a time** with `ijson`, computes the 36 QUT features per sample, and writes:
   - `processed/qut_features/X_{train,val,test}.npy`
   - `processed/qut_features/y_{train,val,test}.npy`
   - `processed/qut_features/feature_names.json`  
   Typical split: **140 / 30 / 30** rows (stratified 70% train, 15% val, 15% test from 200 samples).

**Why streaming:** The parsed JSON files are huge on disk because each sample carries long trace lists, even though there are only 200 samples. Streaming avoids loading 18 GB+ into RAM at once.

### Path B — eBPF JSON to the same 36 numbers

1. **`scripts/import_sessions_to_qut.py`** reads each session JSON and calls **`extract_feature_vector()`**:
   - Maps `filetop`, `install`, `opensnoop`, `tcp`, `syscalls`, `patterns` into the **same 36 order** as QUT.
2. Optional **`--blend-qut-dir`** loads up to **`--blend-qut-max`** rows from `X_train.npy` / `y_train.npy` and **concatenates** them with eBPF rows **before** the train/val/(test or holdout) split. That teaches the model both **QUT scale** and **eBPF scale** in one training matrix.
3. **`--backup-qut-dir`** copies the existing `processed/qut_features/` tree to `processed/backups/qut_features_backup_<timestamp>/` before overwriting.

### Path C — Balanced eBPF pool for fair evaluation

1. **`scripts/build_balanced_ebpf_split.py`** collects labeled JSON from **Desktop `capstone_ebpf_repo`** plus extra benign from **`capstone-main(...)/sessions/`**, drops duplicate filenames, then **undersamples the majority class** so **benign count = malicious count** (e.g. **5 vs 5 → 10 files**).
2. It writes:
   - `data/ebpf_balanced/pool/` — full balanced set (for reporting and optional training input),
   - `data/ebpf_balanced/train_val_pool/` and `data/ebpf_balanced/test_holdout/` — stratified split (default **30%** held out for test).

---

## 4. How data passes through the hybrid model

This is the **`train_hybrid_model.py`** path (class `HybridXGBoostLSTM`), not the older `src/models/train_xgboost.py` / `train_lstm.py` pipeline.

### Step-by-step (conceptual)

1. **Input:** A matrix `X` of shape `(n_samples, 36)` and binary labels `y` (0 benign, 1 malicious).
2. **Scaling:** `StandardScaler` fits on the training fold and normalizes each feature dimension.
3. **XGBoost:** A gradient-boosted tree model fits on scaled `X`. It outputs:
   - Class probabilities (2 columns),
   - **Leaf indices** per tree (encoded and truncated to a fixed width for the LSTM input).
4. **Hybrid vector:** Concatenate **scaled original 36 features**, **XGBoost probabilities**, and **encoded leaf features** into a wider vector per sample.
5. **LSTM:** That vector is reshaped as a short “sequence” (one timestep per row conceptually), passed through a small LSTM stack with dropout, then a sigmoid for **P(malicious)**.
6. **Decision:** Default training uses threshold **0.5** on the LSTM sigmoid for hard class labels.

**Intuition:** XGBoost does the heavy lifting on tabular structure; the LSTM can **reshape errors** using XGBoost’s confidence and path information, which often helps on QUT-style structured noise.

---

## 5. Pipelines (commands)

### 5.1 Hybrid pipeline (recommended for this capstone)

```bash
# 1) Rebuild pure QUT .npy features from parsed JSON (streaming)
python scripts/regenerate_qut_features_streaming.py

# 2) (Optional) Build balanced eBPF JSON folders
python scripts/build_balanced_ebpf_split.py --test-size 0.3

# 3) (Optional) Train on QUT + balanced eBPF pool blended into the same arrays
python scripts/import_sessions_to_qut.py ^
  --sessions-dir data/ebpf_balanced/pool ^
  --blend-qut-dir processed/qut_features ^
  --blend-qut-max 80 ^
  --backup-qut-dir processed/backups

# 4) Train + evaluate hybrid on whatever is currently in processed/qut_features
set PYTHONIOENCODING=utf-8
python train_hybrid_model.py

# 5) Validate on eBPF JSON only (example: balanced pool)
python scripts/validate_sessions_with_qut.py --sessions-dir data/ebpf_balanced/pool
```

On Windows PowerShell, replace `^` with `` ` `` for line continuation or use a single line.

### 5.2 Legacy full trace pipeline (optional)

`run_pipeline.py` walks **raw folders**, calls `parse_traces.py`, `extract_features.py`, and separate XGBoost/LSTM trainers under `src/models/`. That is a **different feature schema** from the 36-QUT hybrid path above.

---

## 6. Results we report

Metrics depend on **which `processed/qut_features` you have loaded** (pure QUT vs blended). After blending, the **30-sample QUT-style test split inside the `.npy` files** is no longer “pure QUT only”; for presentation of **QUT-only** performance, restore from `processed/backups/` or rerun **`regenerate_qut_features_streaming.py`** before `train_hybrid_model.py`.

### 6.1 QUT held-out test (pure QUT features, typical run)

When `processed/qut_features` contains **only** QUT-derived rows (streaming script, no blend), **`train_hybrid_model.py`** reports on **30 test samples** (15 benign, 15 malicious):

| Model | Accuracy | Precision | Recall | F1 | ROC AUC |
|-------|----------|-----------|--------|-----|---------|
| **Hybrid XGBoost + LSTM** | **96.67%** | **1.00** | **0.933** | **0.966** | **~0.94** |
| XGBoost alone (same script) | 96.67% | 1.00 | 0.933 | 0.966 | ~0.96 |

**Hybrid confusion matrix (30 × 30 test):**

|  | Predicted benign | Predicted malicious |
|--|------------------|----------------------|
| **Actual benign** | 15 | 0 |
| **Actual malicious** | 1 | 14 |

So on QUT, the model is **very accurate** with **one malicious** sample slipping through as benign (typical “high precision, slightly timid recall” on a small test slice).

### 6.2 eBPF balanced validation pool (10 sessions)

Command:

```bash
python scripts/validate_sessions_with_qut.py --sessions-dir data/ebpf_balanced/pool
```

This **retrains** the hybrid on whatever is in `processed/qut_features` (often **QUT + eBPF blend** if you ran import with blend), then scores **only** the JSON files in the pool folder.

**Reported metrics (representative run after label fixes and balancing):**

| Metric | Value |
|--------|--------|
| **Accuracy** | **80%** (8 / 10 correct) |
| **Precision (malicious)** | **~0.71** |
| **Recall (malicious)** | **1.00** (all 5 malicious sessions flagged) |
| **F1 (malicious)** | **~0.83** |
| **ROC AUC** | **~0.60** |

**Confusion matrix (10 sessions):**

|  | Predicted benign | Predicted malicious |
|--|------------------|----------------------|
| **Actual benign** | 3 | 2 |
| **Actual malicious** | 0 | 5 |

**How to read this:** Compared with an earlier **unbalanced** 9 benign / 1 malicious check where the **single** malicious case was often **missed**, the balanced pool stresses **both** classes. You now **catch every malicious** file in this pool, with **two benign** sessions (`benign-test` exports) **false-alarmed** as malicious (see `processed/ebpf_validation_predictions.csv`).

**ROC and AUC (short explanation):**  
The ROC curve plots **true positive rate vs false positive rate** as you slide the decision threshold. **AUC** is the area under that curve (1.0 = perfect ranking, 0.5 = random). An AUC around **0.6** on only **10** points means the **ordering** of scores is only moderately aligned with labels; with more labeled eBPF installs, AUC usually stabilizes. To **draw the curve**, load `true_label` and `probability` from `processed/ebpf_validation_predictions.csv` and run `sklearn.metrics.roc_curve` / `matplotlib` in a notebook.

---

## 7. Class balance and lodash / eBPF sessions

### 7.1 Balanced pool (evaluation set under `data/ebpf_balanced/pool/`)

After collecting **Desktop `capstone_ebpf_repo`** plus extra benign from repo sessions, the builder had **10 benign** and **5 malicious** distinct JSON files. It **undersampled benign** to match malicious count:

- **Final pool:** **5 benign + 5 malicious = 10 files** (50/50 split by design).

**Files in the balanced pool (10):**

| File | Package (summary) | True label |
|------|-------------------|------------|
| `npm-1774070156_lodash.json` | lodash | 0 benign |
| `npm-1774429209_lodash.json` | lodash | 0 benign |
| `npm-1775231041_benign-test-1.0.0.tgz.json` | benign-test | 0 |
| `npm-1775231094_benign-test-1.0.0.tgz.json` | benign-test | 0 |
| `npm-1776869115_benign-test-1.0.0.tgz.json` | benign-test | 0 |
| `npm-1775231119_suspicious-test-1.0.0.tgz.json` | suspicious-test | 1 |
| `npm-1776869140_suspicious-test-1.0.0.tgz.json` | suspicious-test | 1 |
| `npm-1776877742_ci-secret-grabber-test-1.0.0.tgz.json` | ci-secret-grabber-test | 1 |
| `npm-1776877789_env-stealer-test-1.0.0.tgz.json` | env-stealer-test | 1 |
| `npm-1776877813_reverse-shell-test-1.0.0.tgz.json` | reverse-shell-test | 1 |

So the pool uses **two lodash eBPF sessions** (different run timestamps). Other lodash captures exist in the repo but are not all in this **balanced** subset because the script caps the benign side to match the number of malicious examples available.

### 7.2 Full lodash session set (repo monitor, not all in the balanced pool)

These are typical **benign lodash** install JSON names that have appeared under `capstone-main(aniruddha_imp)/capstone-main/sessions/` (and copies may exist on the Desktop repo). They are **different runs** of installing lodash:

- `npm-1773841683_lodash.json`
- `npm-1774070156_lodash.json`
- `npm-1774426161_lodash.json`
- `npm-1774427962_lodash.json`
- `npm-1774429209_lodash.json`
- `npm-1774436190_lodash.json`
- `npm-1774436505_lodash.json`

Each file is one **session** (one install trace aggregate). They are useful as **benign diversity** for training and validation even though they are the same package name.

---

## 8. Project structure (updated)

```
Capstone_Implementation/
├── capstone-main(aniruddha_imp)/   # eBPF monitor source + default sessions/
├── configs/                        # YAML (e.g. split ratios)
├── data/
│   ├── raw/                        # QUT raw traces (large)
│   ├── processed/                  # Parsed QUT JSON, features, splits
│   └── ebpf_balanced/              # Built by build_balanced_ebpf_split.py
│       ├── pool/
│       ├── train_val_pool/
│       └── test_holdout/
├── processed/
│   ├── qut_features/               # Hybrid training .npy (pure or blended)
│   ├── qut_features_holdout/     # When using --holdout-dir import path
│   ├── backups/                    # Timestamped copies of qut_features
│   └── ebpf_validation_predictions.csv
├── scripts/
│   ├── regenerate_qut_features_streaming.py
│   ├── import_sessions_to_qut.py
│   ├── validate_sessions_with_qut.py
│   ├── build_balanced_ebpf_split.py
│   ├── extract_qut_features_only.py
│   └── extract_qut36_features.py
├── src/                            # QUT feature extractor, parsers, legacy models
├── train_hybrid_model.py           # Hybrid XGBoost + LSTM trainer
├── run_pipeline.py                 # Legacy full-trace pipeline (optional)
└── trained_models/hybrid_model/    # Saved hybrid artifacts
```

---

## 9. Dependencies and Python

- See **`requirements.txt`**. The streaming QUT script needs **`ijson`**.
- On Windows, if **`train_hybrid_model.py`** crashes while printing box characters, run with  
  `set PYTHONIOENCODING=utf-8` (or `$env:PYTHONIOENCODING="utf-8"` in PowerShell).

---

## 10. Quick glossary

| Term | Meaning |
|------|---------|
| **QUT-DV25** | Research dataset of benign vs malicious package install traces. |
| **36 features** | One fixed-length numeric vector per sample, comparable between QUT and eBPF JSON. |
| **Hybrid** | XGBoost plus LSTM stacked; final probability from LSTM sigmoid. |
| **AUC / ROC** | Summary of how well scores rank benign vs malicious across thresholds. |
| **Balanced pool** | Same count of benign and malicious JSON files so accuracy is not “cheated” by class imbalance. |

If you add more labeled malicious JSON under **`capstone_ebpf_repo`**, rerun **`build_balanced_ebpf_split.py`** and optionally the **import → train → validate** sequence so metrics reflect the new distribution.
