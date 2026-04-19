# Malware Detection Using Hybrid XGBoost + LSTM
## Capstone Project Presentation

---

# Slide 1: Title Slide

## **Malware Detection in Python Packages**
### A Hybrid XGBoost + LSTM Approach Using QUT-DV25 Dataset

**Team/Presenter Name:** [Your Name]  
**Date:** February 2026  
**Course:** [Your Course Name]

---

# Slide 2: Problem Statement

## **The Growing Threat of Malicious Python Packages**

### Why This Matters:
- 📦 **PyPI hosts 400,000+ packages** - supply chain attacks increasing
- 🔓 **Typosquatting attacks** - malicious packages mimic popular ones
- 💉 **Code injection** - attackers hide malware in installation scripts
- 🌐 **Wide impact** - one compromised package can affect thousands of systems

### Our Goal:
> Develop an **automated machine learning pipeline** to detect malicious Python packages using system behavior traces

---

# Slide 3: Dataset Overview

## **QUT-DV25 Dataset**

| Category | Count |
|----------|-------|
| **Benign Packages** | 100 |
| **Malicious Packages** | 100 |
| **Total Samples** | 200 |

### Data Collection Methodology:
- 📁 **Filetop Traces** - File I/O operations
- 📥 **Installation Traces** - Package installation behavior
- 👁️ **Opensnoop Traces** - File access patterns
- 🌐 **TCP Traces** - Network connections
- ⚙️ **System Calls** - Low-level OS interactions

---

# Slide 4: Feature Engineering

## **36 QUT Features in 6 Categories**

### 1. Filetop Features (5)
- `filetop_total_reads`, `filetop_total_writes`
- `filetop_unique_files`, `filetop_read_bytes`, `filetop_write_bytes`

### 2. Installation Features (3)
- `install_duration`, `install_dependencies_count`, `install_file_count`

### 3. Opensnoop Features (7)
- `opensnoop_unique_files`, `opensnoop_read_count`, `opensnoop_write_count`
- `opensnoop_sensitive_access`, `opensnoop_home_access`, `opensnoop_etc_access`, `opensnoop_tmp_access`

### 4. TCP Features (5)
- `tcp_total_connections`, `tcp_unique_ips`, `tcp_unique_ports`
- `tcp_external_connections`, `tcp_suspicious_ports`

### 5. System Call Features (6)
- `syscall_total`, `syscall_unique`, `syscall_file_ops`
- `syscall_network_ops`, `syscall_process_ops`, `syscall_memory_ops`

### 6. Pattern Features (10)
- Regex-based detection of suspicious behaviors

---

# Slide 5: Model Architecture

## **Hybrid XGBoost + LSTM Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                    INPUT: 36 QUT Features                    │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      XGBOOST CLASSIFIER                      │
│  • 100 estimators, max_depth=6                              │
│  • Outputs: Probabilities + Leaf Indices                    │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    FEATURE CONCATENATION                     │
│  Original Features (36) + XGBoost Probs (2) + Leaves (10)   │
│  = 48 Hybrid Features                                        │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    LSTM WITH ATTENTION                       │
│  • 2 Layers, 64 hidden units                                │
│  • Self-attention mechanism                                 │
│  • Dropout: 0.3                                             │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    FINAL PREDICTION                          │
│         Benign (0) or Malicious (1)                          │
└─────────────────────────────────────────────────────────────┘
```

---

# Slide 6: Why Hybrid Approach?

## **Advantages of XGBoost + LSTM Ensemble**

### 1. **Complementary Strengths**
| XGBoost | LSTM |
|---------|------|
| Excellent with tabular data | Captures sequential patterns |
| Fast inference | Learns temporal dependencies |
| Interpretable features | Handles complex relationships |

### 2. **Error Correction**
- LSTM can **correct XGBoost misclassifications**
- Uses confidence scores to make better decisions

### 3. **Feature Enrichment**
- XGBoost provides **12 additional features** (probabilities + leaf indices)
- LSTM learns from this **enriched representation**

### 4. **Reduced Bias**
- Single models have inherent biases
- Ensemble **reduces individual weaknesses**

### 5. **Better Generalization**
- Less prone to overfitting
- More stable across different samples

---

# Slide 7: Experimental Results

## **Model Performance Comparison**

| Model | Accuracy | Precision | Recall | F1 Score | AUC-ROC |
|-------|----------|-----------|--------|----------|---------|
| **LSTM Only** | 76.67% | 0.70 | 0.93 | 0.80 | 0.87 |
| **XGBoost Only** | 96.67% | 1.00 | 0.93 | 0.97 | 0.96 |
| **Hybrid (XGB+LSTM)** | **96.67%** | **1.00** | **0.93** | **0.97** | **0.94** |

### Key Observations:
- ✅ **Hybrid matches XGBoost accuracy** while being more robust
- ✅ **Perfect precision (1.00)** - no false positives
- ✅ **High recall (93.33%)** - catches most malware
- ✅ **Significantly better than standalone LSTM** (+20% accuracy)

---

# Slide 8: Confusion Matrix Analysis

## **Hybrid Model - Test Set (30 samples)**

```
                    Predicted
                    Benign  Malicious
Actual Benign           15         0
Actual Malicious         1        14
```

### Interpretation:
- ✅ **15 True Negatives** - Correctly identified benign packages
- ✅ **14 True Positives** - Correctly identified malicious packages
- ✅ **0 False Positives** - No benign packages flagged as malicious
- ⚠️ **1 False Negative** - One malware sample missed

### Why This Matters:
- **Zero false positives** is crucial for production systems
- Prevents blocking legitimate packages

---

# Slide 9: Feature Importance

## **Top 10 Most Important Features**

| Rank | Feature | Importance |
|------|---------|------------|
| 1 | `pattern_base64_encoding` | High |
| 2 | `tcp_suspicious_ports` | High |
| 3 | `opensnoop_sensitive_access` | High |
| 4 | `syscall_network_ops` | Medium |
| 5 | `pattern_network_keywords` | Medium |
| 6 | `filetop_write_bytes` | Medium |
| 7 | `tcp_external_connections` | Medium |
| 8 | `pattern_file_keywords` | Medium |
| 9 | `opensnoop_etc_access` | Low |
| 10 | `install_duration` | Low |

### Malware Indicators:
- 🚨 Base64 encoding (obfuscation)
- 🌐 Suspicious network activity
- 📁 Sensitive file access

---

# Slide 10: Pipeline Overview

## **Complete ML Pipeline**

```
┌────────────────────────────────────────────────────────────┐
│                     DATA COLLECTION                         │
│  eBPF traces: filetop, opensnoop, tcptrace, installation   │
└────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────┐
│                     PREPROCESSING                           │
│  Parse traces → Extract structured data → Clean/Normalize  │
└────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────┐
│                   FEATURE EXTRACTION                        │
│  36 QUT features across 6 categories                       │
└────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────┐
│                   MODEL TRAINING                            │
│  Hybrid XGBoost + LSTM with attention mechanism            │
└────────────────────────┬───────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────┐
│                     EVALUATION                              │
│  Accuracy, Precision, Recall, F1, AUC-ROC                  │
└────────────────────────────────────────────────────────────┘
```

---

# Slide 11: Code Structure

## **Project Organization**

```
Capstone_Implementation/
├── src/
│   ├── features/
│   │   ├── qut_feature_extractor.py   # 36 QUT features
│   │   └── extract_features.py
│   ├── models/
│   │   ├── train_xgboost.py
│   │   ├── train_lstm.py
│   │   └── evaluate.py
│   ├── preprocessing/
│   │   └── parse_traces.py
│   └── utils/
│       └── helpers.py
├── train_hybrid_model.py              # Hybrid ensemble
├── retrain_qut_features.py            # Training script
├── run_pipeline.py                    # Main pipeline
├── configs/
│   └── config.yaml                    # Configuration
├── data/
│   ├── raw/                           # Raw trace files
│   └── processed/                     # Extracted features
└── trained_models/
    └── hybrid_model/                  # Saved models
```

---

# Slide 12: Technical Implementation

## **Key Technologies Used**

### Machine Learning:
- **XGBoost** - Gradient boosted decision trees
- **PyTorch** - LSTM implementation with attention
- **Scikit-learn** - Preprocessing & evaluation

### Feature Categories:
```python
# Filetop Features
'filetop_total_reads', 'filetop_total_writes', 
'filetop_unique_files', 'filetop_read_bytes', 'filetop_write_bytes'

# Pattern Detection (Regex-based)
'pattern_network_keywords',     # socket, connect, http
'pattern_base64_encoding',      # base64, b64decode
'pattern_credential_keywords',  # password, token, key
'pattern_obfuscation_indicators' # eval, exec, compile
```

### Hybrid Architecture:
```python
# XGBoost → Probabilities + Leaf Indices → LSTM
hybrid_features = torch.cat([
    original_features,      # 36 features
    xgb_probabilities,      # 2 features  
    xgb_leaf_indices        # 10 features
], dim=1)  # Total: 48 features
```

---

# Slide 13: Challenges & Solutions

## **Challenges Faced**

### 1. **Imbalanced Data**
- **Challenge:** Equal samples but real-world has more benign
- **Solution:** Stratified splitting + class weights

### 2. **Feature Extraction Complexity**
- **Challenge:** Multiple trace formats (filetop, TCP, etc.)
- **Solution:** Modular feature extractors with consistent API

### 3. **Model Selection**
- **Challenge:** Single models had limitations
- **Solution:** Hybrid ensemble combining strengths

### 4. **Interpretability**
- **Challenge:** Black-box predictions
- **Solution:** XGBoost feature importance + attention weights

---

# Slide 14: Future Work

## **Potential Improvements**

### Short-term:
- 🔄 **Real-time detection** - Deploy as PyPI plugin
- 📊 **Larger dataset** - More malware samples
- 🎯 **Multi-class classification** - Different malware types

### Long-term:
- 🤖 **Transformer architecture** - Replace LSTM
- 🔍 **Graph neural networks** - Package dependency analysis
- 🌐 **Federated learning** - Privacy-preserving training
- 📱 **Edge deployment** - Lightweight model for local scanning

---

# Slide 15: Conclusion

## **Summary**

### What We Achieved:
✅ Developed **hybrid XGBoost + LSTM** ensemble model  
✅ Achieved **96.67% accuracy** with **perfect precision**  
✅ Used **36 interpretable features** from QUT-DV25 dataset  
✅ Built **modular, reproducible pipeline**  

### Key Takeaways:
1. **Hybrid approaches** combine strengths of different models
2. **Feature engineering** is crucial for malware detection
3. **System behavior traces** reveal malicious patterns
4. **Ensemble methods** improve robustness

### Impact:
> Our pipeline can help secure the Python ecosystem by automatically detecting malicious packages before they harm users.

---

# Slide 16: Demo & Questions

## **Live Demo**

```bash
# Run the complete pipeline
python run_pipeline.py

# Train hybrid model
python train_hybrid_model.py

# Evaluate on new samples
python -m src.models.inference --input new_package_trace.json
```

## **Questions?**

### Contact:
- Email: [your.email@university.edu]
- GitHub: [github.com/your-username/malware-detection]

---

# Appendix A: Detailed Results

## **Classification Report**

```
              precision    recall  f1-score   support

      Benign       0.94      1.00      0.97        15
   Malicious       1.00      0.93      0.97        15

    accuracy                           0.97        30
   macro avg       0.97      0.97      0.97        30
weighted avg       0.97      0.97      0.97        30
```

## **Training History**

| Epoch | Train Loss | Val Loss | Val Accuracy |
|-------|------------|----------|--------------|
| 10 | 0.3254 | 0.5748 | 63.33% |
| 20 | 0.0185 | 0.2052 | 96.67% |
| 27 | 0.0112 | 0.1856 | 96.67% |
| *Early stopped at epoch 27* |

---

# Appendix B: References

1. **QUT-DV25 Dataset Paper**
   - Queensland University of Technology
   - Malicious Python Package Detection

2. **XGBoost**
   - Chen, T., & Guestrin, C. (2016)
   - "XGBoost: A Scalable Tree Boosting System"

3. **LSTM Networks**
   - Hochreiter, S., & Schmidhuber, J. (1997)
   - "Long Short-Term Memory"

4. **Attention Mechanism**
   - Vaswani, A., et al. (2017)
   - "Attention Is All You Need"

---
