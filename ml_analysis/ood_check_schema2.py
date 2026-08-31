"""
Out-of-Distribution Check - Schema 2.0.0
========================================
Re-run the OOD probe with corrected feature alignment.

Key changes from original:
1. Use pN_count columns (not keyword counting) as numeric features
2. On QUT side, only use Pattern_1..5 (6-10 are empty in our captures)
3. Ensure identical transforms on both sides
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neighbors import NearestNeighbors
from scipy import stats
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

QUT_BASE = Path(r"c:\Users\ksj42\Downloads\Desktop\College\Capstone_research\Harvard_Datasets\QUT-DV25_extracted\QUT-DV25_Datasets\QUT-DV25_Processed_Datasets")
SCRIPT_DIR = Path(__file__).parent
PYPI_SAMPLE = SCRIPT_DIR / "pypi-sample-3-schema2.csv"
CORPUS_17 = SCRIPT_DIR / "corpus-17-schema2.csv"
OUTPUT_DIR = SCRIPT_DIR / "outputs"

# Features that are comparable between QUT-DV25 and our captures
# Excluding pattern features for now - will handle separately
NUMERIC_FEATURES = [
    'read_processes', 'write_processes', 'read_data_transfer_kb', 'write_data_transfer_kb',
    'file_access_processes', 'total_dependencies', 'direct_dependencies', 'indirect_dependencies',
    'root_dir_access', 'temp_dir_access', 'home_dir_access', 'user_dir_access',
    'sys_dir_access', 'etc_dir_access', 'other_dir_access', 'state_transitions',
    'local_ips', 'remote_ips', 'local_ports', 'remote_ports',
    'io_ops', 'file_ops', 'network_ops', 'time_ops', 'security_ops', 'process_ops'
]

# Pattern count features (schema 2.0.0)
PATTERN_COUNT_FEATURES = ['p1_count', 'p2_count', 'p3_count', 'p4_count', 'p5_count']

# ============================================================================
# LOAD QUT-DV25 WITH PROPER FEATURE EXTRACTION
# ============================================================================

def load_qut_dataset():
    """Load QUT-DV25 with feature extraction matching our schema 2.0.0."""
    print("=" * 70)
    print("LOADING QUT-DV25 TRAINING DATA (Schema 2.0.0 aligned)")
    print("=" * 70)
    
    filetop = pd.read_csv(QUT_BASE / "QUT-DV25_Filetop_Traces" / "QUT-DV25_Filetop_Traces.csv")
    syscall = pd.read_csv(QUT_BASE / "QUT-DV25_SysCall_Traces" / "QUT-DV25_SysCall_Traces.csv")
    tcp = pd.read_csv(QUT_BASE / "QUT-DV25_TCP_Traces" / "QUT-DV25_TCP_Traces.csv")
    opensnoop = pd.read_csv(QUT_BASE / "QUT-DV25_Opensnoop_Traces" / "QUT-DV25_Opensnoop_Traces.csv")
    install = pd.read_csv(QUT_BASE / "QUT-DV25_Install_Traces" / "QUT-DV25_Install_Traces.csv")
    pattern = pd.read_csv(QUT_BASE / "QUT-DV25_Pattern_Traces" / "QUT-DV25_Pattern_Traces.csv")
    
    merged = filetop[['Package_Name', 'Level']].copy()
    
    # Filetop features - count comma-separated elements
    merged['read_processes'] = filetop['Read_Processes'].fillna('').apply(
        lambda x: len([p for p in str(x).split(',') if p.strip()]) if str(x).strip() else 0
    )
    merged['write_processes'] = filetop['Write_Processes'].fillna('').apply(
        lambda x: len([p for p in str(x).split(',') if p.strip()]) if str(x).strip() else 0
    )
    merged['file_access_processes'] = filetop['File_Access_Processes'].fillna('').apply(
        lambda x: len([p for p in str(x).split(',') if p.strip()]) if str(x).strip() else 0
    )
    merged['read_data_transfer_kb'] = pd.to_numeric(filetop['Total_Read_Data_Transfer'], errors='coerce').fillna(0) / 1024
    merged['write_data_transfer_kb'] = pd.to_numeric(filetop['Total_Write_Data_Transfer'], errors='coerce').fillna(0) / 1024
    
    # Syscall features
    syscall_map = {
        'IO_Operations': 'io_ops',
        'File_Operations': 'file_ops',
        'Network_Operations': 'network_ops',
        'Time_Operations': 'time_ops',
        'Security_Operations': 'security_ops',
        'Process_Management_Operations': 'process_ops'
    }
    syscall_subset = syscall[['Package_Name'] + list(syscall_map.keys())].copy()
    for old_col, new_col in syscall_map.items():
        syscall_subset[new_col] = pd.to_numeric(syscall_subset[old_col], errors='coerce').fillna(0)
    syscall_subset = syscall_subset[['Package_Name'] + list(syscall_map.values())]
    merged = merged.merge(syscall_subset, on='Package_Name', how='left')
    
    # TCP features
    tcp_map = {
        'Total_Entries': 'state_transitions',
        'Local_IP_Address_Access': 'local_ips',
        'Remote_IP_Address_Access': 'remote_ips',
        'Local_Port_Access': 'local_ports',
        'Remote_Port_Access': 'remote_ports'
    }
    tcp_subset = tcp[['Package_Name'] + list(tcp_map.keys())].copy()
    for old_col, new_col in tcp_map.items():
        tcp_subset[new_col] = pd.to_numeric(tcp_subset[old_col], errors='coerce').fillna(0)
    tcp_subset = tcp_subset[['Package_Name'] + list(tcp_map.values())]
    merged = merged.merge(tcp_subset, on='Package_Name', how='left')
    
    # Opensnoop features
    opensnoop_map = {
        'Root_DIR_Installation': 'root_dir_access',
        'Temporary_DIR_Installation': 'temp_dir_access',
        'Home_DIR_Installation': 'home_dir_access',
        'User_Access': 'user_dir_access',
        'Sys_Access': 'sys_dir_access',
        'Etc_DIR_Installation': 'etc_dir_access',
        'Other_DIR_Installation': 'other_dir_access'
    }
    opensnoop_subset = opensnoop[['Package_Name'] + list(opensnoop_map.keys())].copy()
    for old_col, new_col in opensnoop_map.items():
        opensnoop_subset[new_col] = pd.to_numeric(opensnoop_subset[old_col], errors='coerce').fillna(0)
    opensnoop_subset = opensnoop_subset[['Package_Name'] + list(opensnoop_map.values())]
    merged = merged.merge(opensnoop_subset, on='Package_Name', how='left')
    
    # Install features
    install_map = {
        'Total_Dependencies': 'total_dependencies',
        'Direct_Dependencies': 'direct_dependencies',
        'Indirect_Dependencies': 'indirect_dependencies'
    }
    install_subset = install[['Package_Name'] + list(install_map.keys())].copy()
    for old_col, new_col in install_map.items():
        install_subset[new_col] = pd.to_numeric(install_subset[old_col], errors='coerce').fillna(0)
    install_subset = install_subset[['Package_Name'] + list(install_map.values())]
    merged = merged.merge(install_subset, on='Package_Name', how='left')
    
    # Pattern features - ONLY Pattern_1..5 as per Anirudha's guidance
    # Label encode the categorical pattern columns
    pattern_subset = pattern[['Package_Name', 'Pattern_1', 'Pattern_2', 'Pattern_3', 'Pattern_4', 'Pattern_5']].copy()
    
    for i in range(1, 6):
        col = f'Pattern_{i}'
        le = LabelEncoder()
        pattern_subset[col] = pattern_subset[col].fillna('MISSING').astype(str)
        pattern_subset[f'p{i}_count'] = le.fit_transform(pattern_subset[col])
    
    pattern_encoded = pattern_subset[['Package_Name', 'p1_count', 'p2_count', 'p3_count', 'p4_count', 'p5_count']]
    merged = merged.merge(pattern_encoded, on='Package_Name', how='left')
    
    merged = merged.fillna(0)
    merged['label'] = merged['Level']
    
    print(f"  Total samples: {len(merged)}")
    print(f"  Benign: {sum(merged['label'] == 0)}")
    print(f"  Malicious: {sum(merged['label'] == 1)}")
    
    return merged

# ============================================================================
# LOAD PROBE DATA (Schema 2.0.0)
# ============================================================================

def load_probe_data():
    """Load PyPI probe and npm control data from schema 2.0.0 files."""
    print("\n" + "=" * 70)
    print("LOADING PROBE AND CONTROL DATA (Schema 2.0.0)")
    print("=" * 70)
    
    corpus = pd.read_csv(CORPUS_17, encoding='utf-8-sig')
    
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
# FEATURE ALIGNMENT CHECK
# ============================================================================

def check_feature_alignment(qut_df, probe_df, name):
    """Verify features are present and report any mismatches."""
    all_features = NUMERIC_FEATURES + PATTERN_COUNT_FEATURES
    
    print(f"\n  Feature check for {name}:")
    missing = [f for f in all_features if f not in probe_df.columns]
    if missing:
        print(f"    WARNING: Missing features: {missing}")
    else:
        print(f"    All {len(all_features)} features present")

# ============================================================================
# PER-FEATURE RANGE CHECK
# ============================================================================

def per_feature_range_check(qut_df, probe_df, probe_name):
    """Check which features fall outside QUT-DV25's 1st-99th percentile range."""
    print(f"\n{'='*70}")
    print(f"PER-FEATURE RANGE CHECK: {probe_name}")
    print("="*70)
    
    all_features = NUMERIC_FEATURES + PATTERN_COUNT_FEATURES
    results = []
    
    for feat in all_features:
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
                bound = "below 1st pctl"
            elif val > p99:
                deviation = (val - p99) / qut_std
                bound = "above 99th pctl"
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
                for _, row in pkg_ood.sort_values('deviation_std', ascending=False).head(5).iterrows():
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
    print(f"{'Package':<40} {'In':>6} {'Out':>6} {'% In':>8}")
    print("-" * 70)
    for _, row in summary.iterrows():
        print(f"{row['package']:<40} {int(row['features_in_range']):>6} {int(row['features_ood']):>6} {row['pct_in_range']:>7.1f}%")
    
    return results_df, summary

# ============================================================================
# NEAREST-NEIGHBOR DISTANCE CHECK
# ============================================================================

def nn_distance_check(qut_df, probe_df, probe_name, scaler):
    """Compute nearest-neighbor distances from probe rows to QUT-DV25."""
    print(f"\n{'='*70}")
    print(f"NEAREST-NEIGHBOR DISTANCE CHECK: {probe_name}")
    print("="*70)
    
    all_features = NUMERIC_FEATURES + PATTERN_COUNT_FEATURES
    available = [f for f in all_features if f in qut_df.columns and f in probe_df.columns]
    
    X_qut = qut_df[available].apply(pd.to_numeric, errors='coerce').fillna(0).values
    X_probe = probe_df[available].apply(pd.to_numeric, errors='coerce').fillna(0).values
    
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
    probe_distances, _ = nn_probe.kneighbors(X_probe_scaled)
    probe_nn_distances = probe_distances.flatten()
    
    results = []
    print(f"\n{probe_name} distances to nearest QUT-DV25 neighbor:")
    print("-" * 70)
    print(f"{'Package':<40} {'NN Dist':>10} {'Std Above':>10} {'Pctl':>8}")
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
        
        print(f"{pkg_name:<40} {dist:>10.4f} {std_above:>10.1f} {percentile:>7.1f}%")
    
    return pd.DataFrame(results), {
        'qut_mean': qut_nn_mean,
        'qut_median': qut_nn_median,
        'qut_std': qut_nn_std,
        'qut_p95': qut_nn_p95,
        'qut_p99': qut_nn_p99
    }

# ============================================================================
# COMPARISON
# ============================================================================

def compare_pypi_vs_npm(pypi_nn, npm_nn, pypi_range, npm_range, qut_stats):
    """Compare PyPI probe vs npm control."""
    print("\n" + "=" * 70)
    print("SIDE-BY-SIDE COMPARISON: PyPI vs npm (Schema 2.0.0)")
    print("=" * 70)
    
    pypi_mean_dist = pypi_nn['nn_distance'].mean()
    npm_mean_dist = npm_nn['nn_distance'].mean()
    
    pypi_mean_std = pypi_nn['std_above_median'].mean()
    npm_mean_std = npm_nn['std_above_median'].mean()
    
    pypi_mean_pctl = pypi_nn['percentile'].mean()
    npm_mean_pctl = npm_nn['percentile'].mean()
    
    pypi_in_range = pypi_range['pct_in_range'].mean()
    npm_in_range = npm_range['pct_in_range'].mean()
    
    print(f"\n{'Metric':<45} {'PyPI (3)':>12} {'npm (14)':>12}")
    print("-" * 70)
    print(f"{'Mean NN distance to QUT-DV25:':<45} {pypi_mean_dist:>12.4f} {npm_mean_dist:>12.4f}")
    print(f"{'Mean std above QUT median:':<45} {pypi_mean_std:>12.1f} {npm_mean_std:>12.1f}")
    print(f"{'Mean percentile in QUT distribution:':<45} {pypi_mean_pctl:>11.1f}% {npm_mean_pctl:>11.1f}%")
    print(f"{'Avg % features in [1st,99th] range:':<45} {pypi_in_range:>11.1f}% {npm_in_range:>11.1f}%")
    print(f"{'QUT-DV25 internal median NN:':<45} {qut_stats['qut_median']:>12.4f} {'(ref)':>12}")
    print(f"{'QUT-DV25 internal 99th pctl NN:':<45} {qut_stats['qut_p99']:>12.4f} {'(ref)':>12}")
    
    print("\n" + "=" * 70)
    print("INTERPRETATION")
    print("=" * 70)
    
    if pypi_mean_dist < npm_mean_dist:
        ratio = npm_mean_dist / pypi_mean_dist
        print(f"""
    PyPI rows are CLOSER to QUT-DV25 than npm rows.
    
    - PyPI mean NN distance: {pypi_mean_dist:.4f}
    - npm mean NN distance: {npm_mean_dist:.4f}
    - npm is {ratio:.1f}x farther from QUT-DV25
    
    - PyPI at {pypi_mean_pctl:.1f}th percentile vs npm at {npm_mean_pctl:.1f}th percentile
    - PyPI feature compliance: {pypi_in_range:.1f}% vs npm: {npm_in_range:.1f}%
    
    CONCLUSION: The ecosystem shift hypothesis has SOME support.
    PyPI captures are closer to the PyPI-trained QUT-DV25 model.
        """)
    else:
        print(f"""
    PyPI rows are NOT closer to QUT-DV25 than npm rows.
    
    - PyPI mean NN distance: {pypi_mean_dist:.4f}
    - npm mean NN distance: {npm_mean_dist:.4f}
    
    CONCLUSION: Ecosystem shift may not be the primary factor.
        """)
    
    both_in_dist = pypi_mean_pctl < 95 and npm_mean_pctl < 95
    both_ood = pypi_mean_pctl >= 99 and npm_mean_pctl >= 99
    
    if both_in_dist:
        print("""
    BOTH PyPI and npm appear to be IN-DISTRIBUTION (< 95th percentile).
    The model should work on both ecosystems.
        """)
    elif both_ood:
        print("""
    BOTH PyPI and npm appear OUT-OF-DISTRIBUTION (>= 99th percentile).
    Neither ecosystem matches QUT-DV25's training distribution.
        """)
    
    return {
        'pypi_mean_nn': pypi_mean_dist,
        'npm_mean_nn': npm_mean_dist,
        'pypi_mean_std': pypi_mean_std,
        'npm_mean_std': npm_mean_std,
        'pypi_mean_pctl': pypi_mean_pctl,
        'npm_mean_pctl': npm_mean_pctl,
        'pypi_feature_compliance': pypi_in_range,
        'npm_feature_compliance': npm_in_range
    }

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("\n" + "#" * 70)
    print("#  OOD CHECK - Schema 2.0.0 (Corrected Feature Alignment)")
    print("#" * 70)
    
    qut_df = load_qut_dataset()
    pypi_rows, npm_rows = load_probe_data()
    
    check_feature_alignment(qut_df, pypi_rows, "PyPI")
    check_feature_alignment(qut_df, npm_rows, "npm")
    
    all_features = NUMERIC_FEATURES + PATTERN_COUNT_FEATURES
    available = [f for f in all_features if f in qut_df.columns]
    X_qut = qut_df[available].apply(pd.to_numeric, errors='coerce').fillna(0).values
    scaler = StandardScaler()
    scaler.fit(X_qut)
    
    pypi_range_results, pypi_range_summary = per_feature_range_check(qut_df, pypi_rows, "PyPI PROBE")
    npm_range_results, npm_range_summary = per_feature_range_check(qut_df, npm_rows, "npm CONTROL")
    
    pypi_nn_results, qut_stats = nn_distance_check(qut_df, pypi_rows, "PyPI PROBE", scaler)
    npm_nn_results, _ = nn_distance_check(qut_df, npm_rows, "npm CONTROL", scaler)
    
    comparison = compare_pypi_vs_npm(pypi_nn_results, npm_nn_results,
                                      pypi_range_summary, npm_range_summary, qut_stats)
    
    OUTPUT_DIR.mkdir(exist_ok=True)
    pypi_nn_results.to_csv(OUTPUT_DIR / "pypi_nn_schema2.csv", index=False)
    npm_nn_results.to_csv(OUTPUT_DIR / "npm_nn_schema2.csv", index=False)
    pd.DataFrame([comparison]).to_csv(OUTPUT_DIR / "ood_comparison_schema2.csv", index=False)
    
    print(f"\n\nResults saved to: {OUTPUT_DIR}")
    
    return comparison

if __name__ == "__main__":
    main()
