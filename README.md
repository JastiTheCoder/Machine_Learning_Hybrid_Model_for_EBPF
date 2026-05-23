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

## Results

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| XGBoost | add-value | add-value | add-value | add-value | add-value |
| BiLSTM | add-value | add-value | add-value | add-value | add-value |
| Ensemble | add-value | add-value | add-value | add-value | add-value |

Note: Results are based on the processed QUT-DV25 feature set and should be interpreted as academic/project validation rather than production-grade malware detection.

## Limitations

- Current validation is based on a limited academic dataset and may not generalize to all real-world PyPI packages.
- Deep temporal behavior modeling is still an area for future improvement.
- More real-world package execution traces are required for stronger production-level validation.
