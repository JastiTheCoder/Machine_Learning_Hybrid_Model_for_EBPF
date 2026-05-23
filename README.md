# eBPF-Based Malware Detection System

## Project Overview
This project uses eBPF (Extended Berkeley Packet Filter) traces to detect malicious PyPI packages
through machine learning analysis of syscalls, file operations, and network behavior.

## Dataset
- **Source**: QUT-DV25 Dataset (Harvard Dataverse)
- **Types of Traces**:
  - Filetop Traces: File I/O operations
  - Installation Traces: Package installation behavior
  - Opensnoop Traces: File open syscalls
  - Pattern Traces: Behavioral patterns
  - PIDs: Process information
  - TCP Traces: Network connections

## Project Structure
```
Capstone_Implementation/
├── data/
│   ├── raw/                    # Raw trace files (copy dataset here)
│   │   ├── benign/
│   │   └── malicious/
│   ├── processed/              # Processed feature files
│   └── splits/                 # Train/val/test splits
├── src/
│   ├── preprocessing/          # Data parsing and cleaning
│   ├── features/               # Feature extraction
│   ├── models/                 # ML models
│   └── utils/                  # Utility functions
├── notebooks/                  # Jupyter notebooks for exploration
├── configs/                    # Configuration files
├── trained_models/             # Saved model weights
└── logs/                       # Training logs
```

## Models
1. **XGBoost**: Fast, lightweight classifier for real-time detection
2. **BiLSTM**: Deep sequence model for syscall pattern analysis
3. **Ensemble**: Combined approach for production

## Usage
```bash
# 1. Parse raw traces
python src/preprocessing/parse_traces.py

# 2. Extract features
python src/features/extract_features.py

# 3. Train models
python src/models/train_xgboost.py
python src/models/train_lstm.py

# 4. Evaluate
python src/models/evaluate.py
```

## Model Performance Results

The table below summarizes the performance of different models used for benign vs malicious package classification using extracted eBPF behavior features.

| Model | Accuracy | Precision | Recall | F1 Score | AUC-ROC |
|---|---:|---:|---:|---:|---:|
| Random Forest | ~92–94% | ~0.90 | ~0.90 | ~0.90 | ~0.93 |
| Gradient Boosting | ~94–95% | ~0.93 | ~0.92 | ~0.92 | ~0.94 |
| LSTM Only | 76.67% | 0.70 | 0.93 | 0.80 | 0.87 |
| XGBoost Only | 96.67% | 1.00 | 0.93 | 0.97 | 0.96 |
| Hybrid XGBoost + LSTM | **96.67%** | **1.00** | **0.93** | **0.97** | **0.94** |

### Result Interpretation

The hybrid model achieved the best overall performance, with an accuracy of **96.67%**, precision of **1.00**, recall of **0.93**, and F1 score of **0.97**. This indicates that the model was highly effective at identifying malicious package behavior while keeping false positives low.

The XGBoost-only model also performed strongly, achieving the same accuracy of **96.67%** and a slightly higher AUC-ROC of **0.96**. This suggests that structured behavioral features extracted from eBPF traces were highly useful for classification.

The LSTM-only model had lower accuracy at **76.67%**, but achieved a recall of **0.93**, meaning it was still able to detect most malicious cases. However, its lower precision indicates that it produced more false positives compared to XGBoost-based models.

### Important Note

These results are based on the available academic/project dataset and controlled validation setup. The model should not be interpreted as production-ready malware detection without further validation on larger, real-world package execution traces.

## Limitations

- Current validation is based on a limited academic dataset and may not generalize to all real-world PyPI packages.
- Deep temporal behavior modeling is still an area for future improvement.
- More real-world package execution traces are required for stronger production-level validation.
