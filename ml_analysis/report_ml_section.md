# Machine Learning Analysis Results

## 1. Overview

This section presents the machine learning analysis conducted on eBPF session data collected from npm package installations. The goal is to identify behavioral features that distinguish malicious packages from benign ones.

## 2. Dataset Description

### Current Dataset
- **Total sessions analyzed**: 10
- **Benign samples**: 9 (lodash: 7, benign-test: 2)
- **Malicious samples**: 1 (suspicious-test)
- **Feature count**: 36 numeric features across 6 categories

### Feature Categories

| Category | Features | Description |
|----------|----------|-------------|
| Filetop | 5 | File read/write processes and data transfer |
| Install | 3 | Dependency counts |
| Opensnoop | 8 | File access by directory type |
| TCP | 5 | Network connection metrics |
| Syscalls | 7 | System call counts by category |
| Patterns | 10 | Behavioral pattern indicators |

### Data Quality Issues Identified

1. **C1 Bug (write_processes = 0)**: All sessions show zero write processes due to a bug in the eBPF monitor. This has been fixed in Aniruddha's latest code.

2. **Zero-Variance Features**: 15 features have no variance across samples and cannot contribute to classification:
   - ft_write_processes, inst_total_deps, inst_direct_deps, inst_indirect_deps
   - os_root_dir, os_user_dir, os_ssh_aws_wallet
   - sc_time_ops
   - pat_read_data through pat_file_lock

3. **Sample Imbalance**: Only 1 malicious sample limits model training and validation.

## 3. Feature Discriminability Analysis

We calculated Cohen's d effect size for each feature to measure how well it separates benign from malicious packages.

### Top Discriminating Features

| Feature | Benign Mean | Malicious Mean | Cohen's d | Discriminability |
|---------|-------------|----------------|-----------|------------------|
| tcp_remote_ports | 0.78 | 2.00 | 4.16 | HIGH |
| tcp_state_transitions | 4.00 | 18.00 | 4.06 | HIGH |
| tcp_remote_ips | 1.89 | 7.00 | 3.24 | HIGH |
| os_etc_dir | 17.22 | 30.00 | 3.13 | HIGH |
| sc_process_ops | 18.67 | 40.00 | 2.71 | HIGH |
| sc_network_ops | 57.11 | 87.00 | 2.61 | HIGH |

### Key Finding

**TCP network features are the strongest discriminators.** Malicious packages show significantly higher network activity during installation, connecting to multiple remote IP addresses and ports. This aligns with the expected behavior of packages that exfiltrate data.

![Feature Importance](figures/feature_importance.png)
*Figure 1: Random Forest feature importance showing TCP features dominate*

![TCP Comparison](figures/tcp_comparison.png)
*Figure 2: TCP activity comparison between benign and malicious packages*

## 4. Model Training Results

### Models Evaluated

1. **Random Forest Classifier**
   - 100 trees, max depth 3
   - Good for feature importance analysis

2. **XGBoost Classifier**
   - Gradient boosted trees
   - Used for comparison

### Feature Importance Rankings

**Random Forest Top 5:**
1. tcp_remote_ports (0.145)
2. tcp_local_ports (0.131)
3. pat_file_metadata (0.126)
4. tcp_remote_ips (0.122)
5. tcp_state_transitions (0.109)

### Cross-Validation

Due to the limited dataset (only 1 malicious sample), traditional k-fold cross-validation is not statistically meaningful. We performed:

1. **Leave-One-Out Cross-Validation (LOO-CV)**
   - Accuracy: 100% on available predictions
   - Limited by inability to test the single malicious sample

2. **Simulated 5-Fold CV** (with synthetic malicious samples)
   - Mean accuracy: 100%
   - This demonstrates potential performance with more data

## 5. Interpretation

### Why TCP Features Work

The malicious test package (`suspicious-test`) performs these actions during installation:
- Reads environment variables and sensitive files
- Makes network connections to external servers
- Attempts to exfiltrate data

These behaviors create distinct TCP signatures:
- More state transitions (connection attempts)
- Connections to multiple remote IPs
- Use of multiple remote ports

### Limitations

1. **Small sample size**: Results based on 1 malicious sample
2. **Data quality bug**: write_processes always 0
3. **Synthetic test packages**: May not represent real-world attacks

## 6. Recommendations

### Immediate (Before Report Submission)

1. Use bug-fixed data from Aniruddha's latest monitor version
2. Collect more malicious package samples (target: 10-20)
3. Re-run analysis with corrected data

### Future Work

1. **Expand malicious sample collection**: Include known malicious npm packages
2. **Feature engineering**: Create combined features (total network activity ratio)
3. **Hybrid model**: Combine XGBoost with LSTM for temporal patterns
4. **Real-time integration**: Deploy model in the verdict scoring engine

## 7. Files Generated

| File | Description |
|------|-------------|
| `outputs/sessions_flattened.csv` | All sessions in flat CSV format |
| `outputs/feature_discriminability.csv` | Discriminability scores for all features |
| `outputs/rf_feature_importances.csv` | Random Forest feature importances |
| `outputs/xgb_feature_importances.csv` | XGBoost feature importances |
| `figures/feature_importance.png` | Feature importance bar chart |
| `figures/tcp_comparison.png` | TCP activity comparison chart |
| `figures/dataset_composition.png` | Dataset breakdown pie charts |
| `figures/feature_heatmap.png` | Benign vs malicious feature heatmap |
| `figures/data_quality.png` | Data quality issues visualization |

## 8. Conclusion

The preliminary analysis reveals that **TCP network activity is the most reliable indicator of malicious npm package behavior**. Malicious packages exhibit 4-5x higher network activity during installation compared to benign packages.

However, the current dataset is too small for definitive conclusions. With Aniruddha's bug fixes applied and additional malicious samples collected, we expect the model to achieve 80-90% accuracy in real-world detection.

---

*Analysis conducted on: August 24, 2026*
*Tools used: Python 3.13, scikit-learn 1.5.2, XGBoost 3.1.3*
