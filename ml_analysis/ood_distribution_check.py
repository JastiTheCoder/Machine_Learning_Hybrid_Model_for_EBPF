"""
Out-of-Distribution (OOD) Check: PyPI vs npm against QUT-DV25
=============================================================
This script checks whether the 3 PyPI probe rows fall inside QUT-DV25's
distribution, using the 24 npm rows as a negative control (known OOD).

Analysis requested by Anirudha - NOT a classifier accuracy test (3 samples
is too few for that), but a distribution membership check.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import NearestNeighbors
from scipy import stats
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

QUT_BASE = Path(r"c:\Users\ksj42\Downloads\Desktop\College\Capstone_research\Harvard_Datasets\QUT-DV25_extracted\QUT-DV25_Datasets\QUT-DV25_Processed_Datasets")
SCRIPT_DIR = Path(__file__).parent
PYPI_SAMPLE = SCRIPT_DIR / "pypi-sample-3.csv"
CORPUS_27 = SCRIPT_DIR / "corpus-27.csv"
OUTPUT_DIR = SCRIPT_DIR / "outputs"

FEATURE_COLS = [
    'read_processes', 'write_processes', 'read_data_transfer_kb', 'write_data_transfer_kb',
    'file_access_processes', 'total_dependencies', 'direct_dependencies', 'indirect_dependencies',
    'root_dir_access', 'temp_dir_access', 'home_dir_access', 'user_dir_access',
    'sys_dir_access', 'etc_dir_access', 'other_dir_access', 'state_transitions',
    'local_ips', 'remote_ips', 'local_ports', 'remote_ports',
    'io_ops', 'file_ops', 'network_ops', 'time_ops', 'security_ops', 'process_ops',
    'p1_file_metadata', 'p2_read_data', 'p3_write_data', 'p4_socket_create',
    'p5_process_create', 'p6_memory_map', 'p7_fd_manage', 'p8_ipc',
    'p9_file_lock', 'p10_error_handle'
]

# ============================================================================
# STEP 1: LOAD QUT-DV25 DATASET
# ============================================================================

def load_qut_dataset():
    """Load and merge all QUT-DV25 CSV files into feature matrix."""
    print("=" * 70)
    print("LOADING QUT-DV25 TRAINING DATA")
    print("=" * 70)
    
    filetop = pd.read_csv(QUT_BASE / "QUT-DV25_Filetop_Traces" / "QUT-DV25_Filetop_Traces.csv")
    syscall = pd.read_csv(QUT_BASE / "QUT-DV25_SysCall_Traces" / "QUT-DV25_SysCall_Traces.csv")
    tcp = pd.read_csv(QUT_BASE / "QUT-DV25_TCP_Traces" / "QUT-DV25_TCP_Traces.csv")
    opensnoop = pd.read_csv(QUT_BASE / "QUT-DV25_Opensnoop_Traces" / "QUT-DV25_Opensnoop_Traces.csv")
    install = pd.read_csv(QUT_BASE / "QUT-DV25_Install_Traces" / "QUT-DV25_Install_Traces.csv")
    pattern = pd.read_csv(QUT_BASE / "QUT-DV25_Pattern_Traces" / "QUT-DV25_Pattern_Traces.csv")
    
    merged = filetop[['Package_Name', 'Level']].copy()
    
    merged['read_processes'] = pd.to_numeric(filetop['Read_Processes'].str.split(',').str.len(), errors='coerce').fillna(0)
    merged['write_processes'] = pd.to_numeric(filetop['Write_Processes'].str.split(',').str.len(), errors='coerce').fillna(0)
    merged['read_data_transfer_kb'] = pd.to_numeric(filetop['Total_Read_Data_Transfer'], errors='coerce').fillna(0) / 1024
    merged['write_data_transfer_kb'] = pd.to_numeric(filetop['Total_Write_Data_Transfer'], errors='coerce').fillna(0) / 1024
    merged['file_access_processes'] = pd.to_numeric(filetop['File_Access_Processes'].str.split(',').str.len(), errors='coerce').fillna(0)
    
    syscall_merged = syscall[['Package_Name', 'File_Operations', 'Network_Operations', 
                              'IO_Operations', 'Process_Management_Operations',
                              'Memory_Operations', 'Security_Operations', 'Time_Operations',
                              'Miscellaneous_Operations']].copy()
    merged = merged.merge(syscall_merged, on='Package_Name', how='left')
    merged['file_ops'] = pd.to_numeric(merged['File_Operations'], errors='coerce').fillna(0)
    merged['network_ops'] = pd.to_numeric(merged['Network_Operations'], errors='coerce').fillna(0)
    merged['io_ops'] = pd.to_numeric(merged['IO_Operations'], errors='coerce').fillna(0)
    merged['process_ops'] = pd.to_numeric(merged['Process_Management_Operations'], errors='coerce').fillna(0)
    merged['security_ops'] = pd.to_numeric(merged['Security_Operations'], errors='coerce').fillna(0)
    merged['time_ops'] = pd.to_numeric(merged['Time_Operations'], errors='coerce').fillna(0)
    
    tcp_merged = tcp[['Package_Name', 'Total_Entries', 'Local_IP_Address_Access',
                      'Remote_IP_Address_Access', 'Local_Port_Access', 'Remote_Port_Access']].copy()
    merged = merged.merge(tcp_merged, on='Package_Name', how='left')
    merged['state_transitions'] = pd.to_numeric(merged['Total_Entries'], errors='coerce').fillna(0)
    merged['local_ips'] = pd.to_numeric(merged['Local_IP_Address_Access'], errors='coerce').fillna(0)
    merged['remote_ips'] = pd.to_numeric(merged['Remote_IP_Address_Access'], errors='coerce').fillna(0)
    merged['local_ports'] = pd.to_numeric(merged['Local_Port_Access'], errors='coerce').fillna(0)
    merged['remote_ports'] = pd.to_numeric(merged['Remote_Port_Access'], errors='coerce').fillna(0)
    
    opensnoop_cols = opensnoop[['Package_Name', 'Root_DIR_Installation', 'Temporary_DIR_Installation',
                                 'Home_DIR_Installation', 'User_Access', 'Sys_Access', 
                                 'Etc_DIR_Installation', 'Other_DIR_Installation']].copy()
    merged = merged.merge(opensnoop_cols, on='Package_Name', how='left')
    merged['etc_dir_access'] = pd.to_numeric(merged['Etc_DIR_Installation'], errors='coerce').fillna(0)
    merged['home_dir_access'] = pd.to_numeric(merged['Home_DIR_Installation'], errors='coerce').fillna(0)
    merged['root_dir_access'] = pd.to_numeric(merged['Root_DIR_Installation'], errors='coerce').fillna(0)
    merged['sys_dir_access'] = pd.to_numeric(merged['Sys_Access'], errors='coerce').fillna(0)
    merged['temp_dir_access'] = pd.to_numeric(merged['Temporary_DIR_Installation'], errors='coerce').fillna(0)
    merged['user_dir_access'] = pd.to_numeric(merged['User_Access'], errors='coerce').fillna(0)
    merged['other_dir_access'] = pd.to_numeric(merged['Other_DIR_Installation'], errors='coerce').fillna(0)
    
    install_merged = install[['Package_Name', 'Total_Dependencies', 'Direct_Dependencies',
                              'Indirect_Dependencies']].copy()
    merged = merged.merge(install_merged, on='Package_Name', how='left')
    merged['total_dependencies'] = pd.to_numeric(merged['Total_Dependencies'], errors='coerce').fillna(0)
    merged['direct_dependencies'] = pd.to_numeric(merged['Direct_Dependencies'], errors='coerce').fillna(0)
    merged['indirect_dependencies'] = pd.to_numeric(merged['Indirect_Dependencies'], errors='coerce').fillna(0)
    
    pattern_cols_src = [f'Pattern_{i}' for i in range(1, 11)]
    pattern['all_patterns'] = pattern[pattern_cols_src].fillna('').apply(lambda x: ' '.join(x.astype(str)).lower(), axis=1)
    
    pattern_merged = pattern[['Package_Name']].copy()
    pattern_merged['p1_file_metadata'] = pattern['all_patterns'].str.count('fstat|newfstatat')
    pattern_merged['p2_read_data'] = pattern['all_patterns'].str.count('read')
    pattern_merged['p3_write_data'] = pattern['all_patterns'].str.count('write')
    pattern_merged['p4_socket_create'] = pattern['all_patterns'].str.count('socket')
    pattern_merged['p5_process_create'] = pattern['all_patterns'].str.count('fork|clone')
    pattern_merged['p6_memory_map'] = pattern['all_patterns'].str.count('mmap')
    pattern_merged['p7_fd_manage'] = pattern['all_patterns'].str.count('fcntl|dup')
    pattern_merged['p8_ipc'] = pattern['all_patterns'].str.count('pipe')
    pattern_merged['p9_file_lock'] = pattern['all_patterns'].str.count('flock')
    pattern_merged['p10_error_handle'] = pattern['all_patterns'].str.count('error')
    
    merged = merged.merge(pattern_merged, on='Package_Name', how='left')
    for col in ['p1_file_metadata', 'p2_read_data', 'p3_write_data', 'p4_socket_create',
                'p5_process_create', 'p6_memory_map', 'p7_fd_manage', 'p8_ipc', 
                'p9_file_lock', 'p10_error_handle']:
        merged[col] = merged[col].fillna(0)
    
    merged['label'] = merged['Level']
    
    print(f"  Total samples: {len(merged)}")
    print(f"  Benign: {sum(merged['label'] == 0)}")
    print(f"  Malicious: {sum(merged['label'] == 1)}")
    
    return merged

# ============================================================================
# STEP 2: LOAD PROBE DATA
# ============================================================================

def load_probe_data():
    """Load the PyPI probe rows and npm control rows."""
    print("\n" + "=" * 70)
    print("LOADING PROBE AND CONTROL DATA")
    print("=" * 70)
    
    corpus = pd.read_csv(CORPUS_27, encoding='utf-8-sig')
    
    pypi_mask = corpus['package_name'].str.contains('pypi', case=False, na=False)
    pypi_rows = corpus[pypi_mask].copy()
    npm_rows = corpus[~pypi_mask].copy()
    
    print(f"\n  PyPI probe rows: {len(pypi_rows)}")
    for _, row in pypi_rows.iterrows():
        label = "malicious" if row['label'] == 1 else "benign"
        print(f"    - {row['package_name']} ({label})")
    
    print(f"\n  npm control rows: {len(npm_rows)}")
    npm_benign = npm_rows[npm_rows['label'] == 0]
    npm_malicious = npm_rows[npm_rows['label'] == 1]
    print(f"    - Benign: {len(npm_benign)}")
    print(f"    - Malicious: {len(npm_malicious)}")
    
    return pypi_rows, npm_rows

# ============================================================================
# STEP 3: PER-FEATURE RANGE CHECK
# ============================================================================

def per_feature_range_check(qut_df, probe_df, probe_name):
    """Check which features fall outside QUT-DV25's 1st-99th percentile range."""
    print(f"\n{'='*70}")
    print(f"PER-FEATURE RANGE CHECK: {probe_name}")
    print("="*70)
    
    results = []
    
    for feat in FEATURE_COLS:
        if feat not in qut_df.columns or feat not in probe_df.columns:
            continue
            
        qut_vals = pd.to_numeric(qut_df[feat], errors='coerce').fillna(0)
        probe_vals = pd.to_numeric(probe_df[feat], errors='coerce').fillna(0)
        
        p1 = np.percentile(qut_vals, 1)
        p99 = np.percentile(qut_vals, 99)
        qut_mean = qut_vals.mean()
        qut_std = qut_vals.std()
        if qut_std == 0:
            qut_std = 1
        
        for idx, val in enumerate(probe_vals):
            pkg_name = probe_df.iloc[idx]['package_name']
            
            in_range = p1 <= val <= p99
            
            if val < p1:
                deviation = (p1 - val) / qut_std
                bound = "below 1st percentile"
            elif val > p99:
                deviation = (val - p99) / qut_std
                bound = "above 99th percentile"
            else:
                deviation = 0
                bound = "in range"
            
            results.append({
                'package': pkg_name,
                'feature': feat,
                'value': val,
                'qut_p1': p1,
                'qut_p99': p99,
                'qut_mean': qut_mean,
                'qut_std': qut_std,
                'in_range': in_range,
                'deviation_std': deviation,
                'bound': bound
            })
    
    results_df = pd.DataFrame(results)
    
    print(f"\nFeatures OUTSIDE [1st, 99th] percentile range:")
    print("-" * 70)
    
    ood_features = results_df[~results_df['in_range']]
    
    if len(ood_features) == 0:
        print("  ALL features within range!")
    else:
        for pkg in probe_df['package_name'].unique():
            pkg_ood = ood_features[ood_features['package'] == pkg]
            if len(pkg_ood) > 0:
                print(f"\n  {pkg}: {len(pkg_ood)} features out of range")
                for _, row in pkg_ood.sort_values('deviation_std', ascending=False).head(10).iterrows():
                    print(f"    - {row['feature']}: {row['value']:.1f} ({row['bound']}, {row['deviation_std']:.1f} std)")
    
    summary = results_df.groupby('package').agg({
        'in_range': ['sum', 'count']
    }).reset_index()
    summary.columns = ['package', 'features_in_range', 'total_features']
    summary['features_ood'] = summary['total_features'] - summary['features_in_range']
    summary['pct_in_range'] = 100 * summary['features_in_range'] / summary['total_features']
    
    print(f"\n{'='*70}")
    print("SUMMARY: Features in/out of range")
    print("-" * 70)
    print(f"{'Package':<35} {'In Range':>12} {'Out of Range':>12} {'% In Range':>12}")
    print("-" * 70)
    for _, row in summary.iterrows():
        print(f"{row['package']:<35} {int(row['features_in_range']):>12} {int(row['features_ood']):>12} {row['pct_in_range']:>11.1f}%")
    
    return results_df, summary

# ============================================================================
# STEP 4: NEAREST-NEIGHBOR DISTANCE CHECK
# ============================================================================

def nn_distance_check(qut_df, probe_df, probe_name, scaler):
    """
    Compute nearest-neighbor distances from probe rows to QUT-DV25.
    Compare against the distribution of NN distances within QUT-DV25 itself.
    """
    print(f"\n{'='*70}")
    print(f"NEAREST-NEIGHBOR DISTANCE CHECK: {probe_name}")
    print("="*70)
    
    available_features = [f for f in FEATURE_COLS if f in qut_df.columns and f in probe_df.columns]
    
    X_qut = qut_df[available_features].apply(pd.to_numeric, errors='coerce').fillna(0).values
    X_probe = probe_df[available_features].apply(pd.to_numeric, errors='coerce').fillna(0).values
    
    X_qut_scaled = scaler.transform(X_qut)
    X_probe_scaled = scaler.transform(X_probe)
    
    nn_qut = NearestNeighbors(n_neighbors=2, metric='euclidean')
    nn_qut.fit(X_qut_scaled)
    
    qut_distances, _ = nn_qut.kneighbors(X_qut_scaled)
    qut_nn_distances = qut_distances[:, 1]
    
    qut_nn_mean = np.mean(qut_nn_distances)
    qut_nn_std = np.std(qut_nn_distances)
    qut_nn_median = np.median(qut_nn_distances)
    qut_nn_p95 = np.percentile(qut_nn_distances, 95)
    qut_nn_p99 = np.percentile(qut_nn_distances, 99)
    
    print(f"\nQUT-DV25 internal NN distance distribution:")
    print(f"  Mean:   {qut_nn_mean:.4f}")
    print(f"  Median: {qut_nn_median:.4f}")
    print(f"  Std:    {qut_nn_std:.4f}")
    print(f"  95th:   {qut_nn_p95:.4f}")
    print(f"  99th:   {qut_nn_p99:.4f}")
    
    nn_probe = NearestNeighbors(n_neighbors=1, metric='euclidean')
    nn_probe.fit(X_qut_scaled)
    probe_distances, probe_indices = nn_probe.kneighbors(X_probe_scaled)
    probe_nn_distances = probe_distances.flatten()
    
    results = []
    print(f"\n{probe_name} row distances to nearest QUT-DV25 neighbor:")
    print("-" * 70)
    print(f"{'Package':<35} {'NN Dist':>10} {'Std Above':>12} {'Percentile':>12}")
    print("-" * 70)
    
    for idx, (pkg_name, dist) in enumerate(zip(probe_df['package_name'], probe_nn_distances)):
        std_above = (dist - qut_nn_median) / qut_nn_std if qut_nn_std > 0 else 0
        percentile = stats.percentileofscore(qut_nn_distances, dist)
        
        results.append({
            'package': pkg_name,
            'nn_distance': dist,
            'std_above_median': std_above,
            'percentile': percentile,
            'label': probe_df.iloc[idx]['label']
        })
        
        print(f"{pkg_name:<35} {dist:>10.4f} {std_above:>12.1f} {percentile:>11.1f}%")
    
    return pd.DataFrame(results), {
        'qut_mean': qut_nn_mean,
        'qut_median': qut_nn_median,
        'qut_std': qut_nn_std,
        'qut_p95': qut_nn_p95,
        'qut_p99': qut_nn_p99
    }

# ============================================================================
# STEP 5: SIDE-BY-SIDE COMPARISON
# ============================================================================

def compare_pypi_vs_npm(pypi_nn_results, npm_nn_results, pypi_range_summary, npm_range_summary, qut_stats):
    """Compare PyPI probe rows against npm control rows."""
    print("\n" + "=" * 70)
    print("SIDE-BY-SIDE COMPARISON: PyPI vs npm")
    print("=" * 70)
    
    print("\n1. NEAREST-NEIGHBOR DISTANCE COMPARISON")
    print("-" * 70)
    
    pypi_mean_dist = pypi_nn_results['nn_distance'].mean()
    npm_mean_dist = npm_nn_results['nn_distance'].mean()
    
    pypi_mean_std_above = pypi_nn_results['std_above_median'].mean()
    npm_mean_std_above = npm_nn_results['std_above_median'].mean()
    
    pypi_mean_pctl = pypi_nn_results['percentile'].mean()
    npm_mean_pctl = npm_nn_results['percentile'].mean()
    
    print(f"\n{'Metric':<40} {'PyPI (3 rows)':>15} {'npm (24 rows)':>15}")
    print("-" * 70)
    print(f"{'Mean NN distance to QUT-DV25:':<40} {pypi_mean_dist:>15.4f} {npm_mean_dist:>15.4f}")
    print(f"{'Mean std deviations above QUT median:':<40} {pypi_mean_std_above:>15.1f} {npm_mean_std_above:>15.1f}")
    print(f"{'Mean percentile in QUT NN distribution:':<40} {pypi_mean_pctl:>14.1f}% {npm_mean_pctl:>14.1f}%")
    print(f"{'QUT-DV25 internal median NN distance:':<40} {qut_stats['qut_median']:>15.4f} {'(reference)':>15}")
    print(f"{'QUT-DV25 internal 99th pctl NN distance:':<40} {qut_stats['qut_p99']:>15.4f} {'(reference)':>15}")
    
    print("\n2. FEATURE RANGE COMPLIANCE")
    print("-" * 70)
    
    pypi_avg_in_range = pypi_range_summary['pct_in_range'].mean()
    npm_avg_in_range = npm_range_summary['pct_in_range'].mean()
    
    print(f"\n{'Metric':<40} {'PyPI (3 rows)':>15} {'npm (24 rows)':>15}")
    print("-" * 70)
    print(f"{'Avg % features in [1st,99th] range:':<40} {pypi_avg_in_range:>14.1f}% {npm_avg_in_range:>14.1f}%")
    
    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    
    if pypi_mean_dist < npm_mean_dist and pypi_avg_in_range > npm_avg_in_range:
        print("""
    PyPI rows are CLOSER to QUT-DV25 distribution than npm rows.
    
    Evidence:
    - PyPI mean NN distance ({:.4f}) < npm mean NN distance ({:.4f})
    - PyPI feature compliance ({:.1f}%) > npm feature compliance ({:.1f}%)
    - PyPI rows sit at {:.1f}th percentile vs npm at {:.1f}th percentile
    
    Interpretation: The ecosystem shift (npm->PyPI) WAS a major factor in the
    domain shift problem. The PyPI probe rows appear to be IN-DISTRIBUTION
    relative to QUT-DV25 training data, while npm rows remain OUT-OF-DISTRIBUTION.
    
    Next step: Expand PyPI fixture corpus and re-evaluate model accuracy.
        """.format(pypi_mean_dist, npm_mean_dist, pypi_avg_in_range, npm_avg_in_range,
                   pypi_mean_pctl, npm_mean_pctl))
        
    elif pypi_mean_dist >= npm_mean_dist or pypi_avg_in_range <= npm_avg_in_range:
        print("""
    PyPI rows are NOT closer to QUT-DV25 distribution than npm rows.
    
    Evidence:
    - PyPI mean NN distance ({:.4f}) vs npm mean NN distance ({:.4f})
    - PyPI feature compliance ({:.1f}%) vs npm feature compliance ({:.1f}%)
    - PyPI rows sit at {:.1f}th percentile vs npm at {:.1f}th percentile
    
    Interpretation: The ecosystem shift may NOT be the primary factor.
    Both npm and PyPI appear similarly out-of-distribution relative to QUT-DV25.
    The domain shift may be due to other factors (capture methodology, synthetic
    vs real malware, feature extraction differences, etc.)
    
    Next step: Investigate other sources of domain shift before scaling corpus.
        """.format(pypi_mean_dist, npm_mean_dist, pypi_avg_in_range, npm_avg_in_range,
                   pypi_mean_pctl, npm_mean_pctl))
    
    return {
        'pypi_mean_nn_dist': pypi_mean_dist,
        'npm_mean_nn_dist': npm_mean_dist,
        'pypi_mean_std_above': pypi_mean_std_above,
        'npm_mean_std_above': npm_mean_std_above,
        'pypi_mean_pctl': pypi_mean_pctl,
        'npm_mean_pctl': npm_mean_pctl,
        'pypi_avg_feature_compliance': pypi_avg_in_range,
        'npm_avg_feature_compliance': npm_avg_in_range
    }

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("\n" + "#" * 70)
    print("#  OOD DISTRIBUTION CHECK: PyPI vs npm against QUT-DV25")
    print("#" * 70)
    
    qut_df = load_qut_dataset()
    
    pypi_rows, npm_rows = load_probe_data()
    
    available_features = [f for f in FEATURE_COLS if f in qut_df.columns]
    X_qut = qut_df[available_features].apply(pd.to_numeric, errors='coerce').fillna(0).values
    scaler = StandardScaler()
    scaler.fit(X_qut)
    
    pypi_range_results, pypi_range_summary = per_feature_range_check(qut_df, pypi_rows, "PyPI PROBE")
    npm_range_results, npm_range_summary = per_feature_range_check(qut_df, npm_rows, "npm CONTROL")
    
    pypi_nn_results, qut_stats = nn_distance_check(qut_df, pypi_rows, "PyPI PROBE", scaler)
    npm_nn_results, _ = nn_distance_check(qut_df, npm_rows, "npm CONTROL", scaler)
    
    comparison = compare_pypi_vs_npm(pypi_nn_results, npm_nn_results, 
                                      pypi_range_summary, npm_range_summary, qut_stats)
    
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    pypi_range_results.to_csv(OUTPUT_DIR / "pypi_range_check.csv", index=False)
    npm_range_results.to_csv(OUTPUT_DIR / "npm_range_check.csv", index=False)
    pypi_nn_results.to_csv(OUTPUT_DIR / "pypi_nn_distances.csv", index=False)
    npm_nn_results.to_csv(OUTPUT_DIR / "npm_nn_distances.csv", index=False)
    
    summary_df = pd.DataFrame([comparison])
    summary_df.to_csv(OUTPUT_DIR / "ood_comparison_summary.csv", index=False)
    
    print(f"\n\nOutput files saved to: {OUTPUT_DIR}")
    print("  - pypi_range_check.csv")
    print("  - npm_range_check.csv")
    print("  - pypi_nn_distances.csv")
    print("  - npm_nn_distances.csv")
    print("  - ood_comparison_summary.csv")
    
    return comparison

if __name__ == "__main__":
    main()
