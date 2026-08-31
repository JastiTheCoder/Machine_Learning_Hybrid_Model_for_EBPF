# Out-of-Distribution Analysis: PyPI vs npm against QUT-DV25

**Date:** August 29, 2026  
**Analysis by:** Karthik (ML Team)

## Executive Summary

**Conclusion: PyPI rows are FARTHER from QUT-DV25 than npm rows.**

This is the opposite of the expected result. The ecosystem shift (npm → PyPI) does
not solve the domain shift problem—it makes it worse.

| Metric | PyPI (3 rows) | npm (24 rows) | QUT-DV25 Internal |
|--------|---------------|---------------|-------------------|
| Mean NN Distance | **524.89** | 10.28 | 0.92 (median) |
| Std Above Median | **505 σ** | 9 σ | 0 (by definition) |
| Percentile in QUT | 100th | 99.8th | - |
| Features in Range | 78.7% | 73.9% | 100% (by definition) |

Both npm and PyPI are out-of-distribution, but PyPI is **~51x farther** from
QUT-DV25's training manifold.

---

## Analysis Details

### 1. Per-Feature Range Check

#### PyPI Probe Rows (3 samples)

| Package | Features Out of Range | % In Range |
|---------|----------------------|------------|
| ./pypi-benign-test | 8 | 77.8% |
| ./pypi-cred-reader-test | 7 | 80.6% |
| ./pypi-persistence-test | 8 | 77.8% |

**Most extreme outliers for PyPI:**
- `p1_file_metadata`: 2559-2569 (**524 std deviations above 99th percentile**)
- `read_processes`: 9 (8.8 std above)
- `file_access_processes`: 9 (8.8 std above)
- `temp_dir_access`: 2471-2477 (6.9 std above)

#### npm Control Rows (24 samples)

| Package | Features Out of Range | % In Range |
|---------|----------------------|------------|
| lodash (7 rows) | 72 total | 71.4% |
| benign-test-1.0.0.tgz | 17 | 76.4% |
| suspicious-test-1.0.0.tgz | 9 | 75.0% |
| unknown (6 malicious) | 39 total | 78.3% |
| underscore | 10 | 72.2% |
| moment | 10 | 72.2% |
| chalk | 9 | 75.0% |
| axios | 11 | 69.4% |
| uuid | 9 | 75.0% |
| dotenv | 9 | 75.0% |
| debug | 10 | 72.2% |
| ./benign-test-1.0.0.tgz | 18 | 75.0% |

**Most extreme outliers for npm:**
- `write_processes`: 0-2 (11 std below 1st percentile)
- `read_processes`: 1-3 (4-9 std below)
- `p10_error_handle`: 9-18 (4-14 std above)

### 2. Nearest-Neighbor Distance Analysis

#### QUT-DV25 Internal NN Distribution
- Mean: 1.0958
- Median: 0.9227
- Std: 1.0382
- 95th percentile: 2.3671
- 99th percentile: 3.7830

#### PyPI Rows (distance to nearest QUT-DV25 neighbor)
| Package | NN Distance | Std Above Median | Percentile |
|---------|-------------|------------------|------------|
| ./pypi-benign-test | 523.87 | 503.7 σ | 100.0% |
| ./pypi-cred-reader-test | 524.86 | 504.7 σ | 100.0% |
| ./pypi-persistence-test | 525.94 | 505.7 σ | 100.0% |

#### npm Rows (distance to nearest QUT-DV25 neighbor)
| Package | NN Distance | Std Above Median | Percentile |
|---------|-------------|------------------|------------|
| lodash (avg) | 4.9 | 3.8 σ | 99.4% |
| benign-test-1.0.0.tgz (avg) | 10.1 | 8.8 σ | 99.9% |
| suspicious-test-1.0.0.tgz | 8.4 | 7.2 σ | 99.9% |
| unknown (malicious, avg) | 14.0 | 12.6 σ | 100.0% |
| Real npm packages (avg) | 9.3 | 8.1 σ | 99.9% |
| axios | 38.7 | 36.4 σ | 100.0% |

---

## Root Cause Analysis

### The Smoking Gun: `p1_file_metadata`

The `p1_file_metadata` feature (count of fstat/newfstatat syscall patterns) is the
primary driver of the extreme distance:

| Source | p1_file_metadata Value | Status |
|--------|------------------------|--------|
| QUT-DV25 99th percentile | ~5 | Normal |
| npm captures | 2-15 | Slightly above normal |
| PyPI captures | **2559-2569** | **524 std above normal** |

This single feature accounts for almost the entire NN distance for PyPI rows.

### Why This Happens

1. **Different capture methodology**: Our eBPF monitor captures file metadata
   operations differently than QUT-DV25's collection process.

2. **Python vs JavaScript runtime**: pip/Python may generate significantly more
   fstat/newfstatat syscalls during package installation than pip's PyPI
   methodology captured.

3. **Pattern extraction implementation**: Our Go exporter's pattern counting may
   differ from QUT-DV25's methodology.

---

## Implications

### The Ecosystem Shift Hypothesis is REJECTED

The original hypothesis was:
> "The model fails on npm because it was trained on PyPI (QUT-DV25). If we capture
> PyPI data, it should match the training distribution."

**This hypothesis is wrong.** Our PyPI captures are farther from QUT-DV25 than our
npm captures. The domain shift is not caused by the ecosystem difference.

### The Real Problem

The domain shift is caused by **methodological differences**:
1. Different eBPF implementations (ours vs QUT's)
2. Different feature extraction algorithms
3. Different system configurations during capture
4. Synthetic test fixtures vs real malware

---

## Recommendations

### Immediate (Before Report Submission)

1. **Do NOT scale the PyPI fixture corpus** until the `p1_file_metadata`
   discrepancy is understood and resolved.

2. **Investigate the pattern extraction**:
   - How does QUT-DV25 compute Pattern_1 (p1_file_metadata)?
   - How does our Go exporter compute it?
   - Why is ours 500x higher?

3. **Consider feature normalization**: Cap or log-transform extreme features to
   reduce their dominance in distance calculations.

### Alternative Approach

**Train on our own captures instead of QUT-DV25.**

Given that both npm and PyPI captures from our monitor are out-of-distribution
relative to QUT-DV25, we should consider:

1. Collecting more labeled samples using our own monitor
2. Training a model on our own data
3. Evaluating on held-out samples from our own captures

This sidesteps the methodological incompatibility entirely.

---

## Files Generated

| File | Description |
|------|-------------|
| `outputs/pypi_range_check.csv` | Per-feature range check for PyPI rows |
| `outputs/npm_range_check.csv` | Per-feature range check for npm rows |
| `outputs/pypi_nn_distances.csv` | NN distances for PyPI rows |
| `outputs/npm_nn_distances.csv` | NN distances for npm rows |
| `outputs/ood_comparison_summary.csv` | Summary comparison metrics |
| `ood_distribution_check.py` | Analysis script |

---

## Appendix: Feature Column Mapping

Columns 3-39 (36 features, excluding `package_name`, `label`, `severity_score`):

1. read_processes
2. write_processes
3. read_data_transfer_kb
4. write_data_transfer_kb
5. file_access_processes
6. total_dependencies
7. direct_dependencies
8. indirect_dependencies
9. root_dir_access
10. temp_dir_access
11. home_dir_access
12. user_dir_access
13. sys_dir_access
14. etc_dir_access
15. other_dir_access
16. state_transitions
17. local_ips
18. remote_ips
19. local_ports
20. remote_ports
21. io_ops
22. file_ops
23. network_ops
24. time_ops
25. security_ops
26. process_ops
27. p1_file_metadata
28. p2_read_data
29. p3_write_data
30. p4_socket_create
31. p5_process_create
32. p6_memory_map
33. p7_fd_manage
34. p8_ipc
35. p9_file_lock
36. p10_error_handle
