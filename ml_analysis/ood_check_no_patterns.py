"""
Out-of-Distribution Check - NO PATTERN FEATURES
================================================
Re-run the OOD probe using only the 26 non-pattern features.
This removes the pN_count mismatch issue entirely.
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
CORPUS_17 = SCRIPT_DIR / "corpus-17-schema2.csv"
OUTPUT_DIR = SCRIPT_DIR / "outputs"

# ONLY non-pattern features (26 total)
FEATURES = [
    'read_processes', 'write_processes', 'read_data_transfer_kb', 'write_data_transfer_kb',
    'file_access_processes', 'total_dependencies', 'direct_dependencies', 'indirect_dependencies',
    'root_dir_access', 'temp_dir_access', 'home_dir_access', 'user_dir_access',
    'sys_dir_access', 'etc_dir_access', 'other_dir_access', 'state_transitions',
    'local_ips', 'remote_ips', 'local_ports', 'remote_ports',
    'io_ops', 'file_ops', 'network_ops', 'time_ops', 'security_ops', 'process_ops'
]

# ============================================================================
# LOAD DATA
# ============================================================================

def load_qut_dataset():
    """Load QUT-DV25 with only non-pattern features."""
    print("=" * 70)
    print("LOADING QUT-DV25 (26 non-pattern features only)")
    print("=" * 70)
    
    filetop = pd.read_csv(QUT_BASE / "QUT-DV25_Filetop_Traces" / "QUT-DV25_Filetop_Traces.csv")
    syscall = pd.read_csv(QUT_BASE / "QUT-DV25_SysCall_Traces" / "QUT-DV25_SysCall_Traces.csv")
    tcp = pd.read_csv(QUT_BASE / "QUT-DV25_TCP_Traces" / "QUT-DV25_TCP_Traces.csv")
    opensnoop = pd.read_csv(QUT_BASE / "QUT-DV25_Opensnoop_Traces" / "QUT-DV25_Opensnoop_Traces.csv")
    install = pd.read_csv(QUT_BASE / "QUT-DV25_Install_Traces" / "QUT-DV25_Install_Traces.csv")
    
    merged = filetop[['Package_Name', 'Level']].copy()
    
    # Filetop
    merged['read_processes'] = filetop['Read_Processes'].fillna('').apply(
        lambda x: len([p for p in str(x).split(',') if p.strip()]) if str(x).strip() else 0)
    merged['write_processes'] = filetop['Write_Processes'].fillna('').apply(
        lambda x: len([p for p in str(x).split(',') if p.strip()]) if str(x).strip() else 0)
    merged['file_access_processes'] = filetop['File_Access_Processes'].fillna('').apply(
        lambda x: len([p for p in str(x).split(',') if p.strip()]) if str(x).strip() else 0)
    merged['read_data_transfer_kb'] = pd.to_numeric(filetop['Total_Read_Data_Transfer'], errors='coerce').fillna(0) / 1024
    merged['write_data_transfer_kb'] = pd.to_numeric(filetop['Total_Write_Data_Transfer'], errors='coerce').fillna(0) / 1024
    
    # Syscall
    syscall_map = {'IO_Operations': 'io_ops', 'File_Operations': 'file_ops',
                   'Network_Operations': 'network_ops', 'Time_Operations': 'time_ops',
                   'Security_Operations': 'security_ops', 'Process_Management_Operations': 'process_ops'}
    for old, new in syscall_map.items():
        merged = merged.merge(syscall[['Package_Name', old]].rename(columns={old: new}), on='Package_Name', how='left')
        merged[new] = pd.to_numeric(merged[new], errors='coerce').fillna(0)
    
    # TCP
    tcp_map = {'Total_Entries': 'state_transitions', 'Local_IP_Address_Access': 'local_ips',
               'Remote_IP_Address_Access': 'remote_ips', 'Local_Port_Access': 'local_ports',
               'Remote_Port_Access': 'remote_ports'}
    for old, new in tcp_map.items():
        merged = merged.merge(tcp[['Package_Name', old]].rename(columns={old: new}), on='Package_Name', how='left')
        merged[new] = pd.to_numeric(merged[new], errors='coerce').fillna(0)
    
    # Opensnoop
    opensnoop_map = {'Root_DIR_Installation': 'root_dir_access', 'Temporary_DIR_Installation': 'temp_dir_access',
                     'Home_DIR_Installation': 'home_dir_access', 'User_Access': 'user_dir_access',
                     'Sys_Access': 'sys_dir_access', 'Etc_DIR_Installation': 'etc_dir_access',
                     'Other_DIR_Installation': 'other_dir_access'}
    for old, new in opensnoop_map.items():
        merged = merged.merge(opensnoop[['Package_Name', old]].rename(columns={old: new}), on='Package_Name', how='left')
        merged[new] = pd.to_numeric(merged[new], errors='coerce').fillna(0)
    
    # Install
    install_map = {'Total_Dependencies': 'total_dependencies', 'Direct_Dependencies': 'direct_dependencies',
                   'Indirect_Dependencies': 'indirect_dependencies'}
    for old, new in install_map.items():
        merged = merged.merge(install[['Package_Name', old]].rename(columns={old: new}), on='Package_Name', how='left')
        merged[new] = pd.to_numeric(merged[new], errors='coerce').fillna(0)
    
    merged = merged.fillna(0)
    merged['label'] = merged['Level']
    
    print(f"  Samples: {len(merged)} | Benign: {sum(merged['label']==0)} | Malicious: {sum(merged['label']==1)}")
    return merged

def load_probe_data():
    """Load probe data from schema 2.0.0."""
    print("\n" + "=" * 70)
    print("LOADING PROBE DATA")
    print("=" * 70)
    
    corpus = pd.read_csv(CORPUS_17, encoding='utf-8-sig')
    
    pypi_mask = corpus['package_name'].str.contains('pypi', case=False, na=False)
    pypi_rows = corpus[pypi_mask].copy()
    npm_rows = corpus[~pypi_mask].copy()
    
    print(f"  PyPI: {len(pypi_rows)} | npm: {len(npm_rows)}")
    return pypi_rows, npm_rows

# ============================================================================
# ANALYSIS
# ============================================================================

def per_feature_range_check(qut_df, probe_df, name):
    """Check features against QUT's 1st-99th percentile."""
    results = []
    for feat in FEATURES:
        if feat not in qut_df.columns or feat not in probe_df.columns:
            continue
        qut_vals = pd.to_numeric(qut_df[feat], errors='coerce').fillna(0)
        probe_vals = pd.to_numeric(probe_df[feat], errors='coerce').fillna(0)
        
        p1, p99 = np.percentile(qut_vals, 1), np.percentile(qut_vals, 99)
        qut_std = qut_vals.std() or 1
        
        for idx, val in enumerate(probe_vals):
            in_range = p1 <= val <= p99
            if val < p1:
                dev = (p1 - val) / qut_std
            elif val > p99:
                dev = (val - p99) / qut_std
            else:
                dev = 0
            results.append({'package': probe_df.iloc[idx]['package_name'], 'feature': feat,
                           'value': val, 'in_range': in_range, 'deviation': dev})
    
    df = pd.DataFrame(results)
    summary = df.groupby('package').agg({'in_range': ['sum', 'count']}).reset_index()
    summary.columns = ['package', 'in_range', 'total']
    summary['out_of_range'] = summary['total'] - summary['in_range']
    summary['pct_in'] = 100 * summary['in_range'] / summary['total']
    return df, summary

def nn_distance_check(qut_df, probe_df, name, scaler):
    """Compute NN distances."""
    available = [f for f in FEATURES if f in qut_df.columns and f in probe_df.columns]
    
    X_qut = qut_df[available].apply(pd.to_numeric, errors='coerce').fillna(0).values
    X_probe = probe_df[available].apply(pd.to_numeric, errors='coerce').fillna(0).values
    
    X_qut_s = scaler.transform(X_qut)
    X_probe_s = scaler.transform(X_probe)
    
    # QUT internal NN distances
    nn = NearestNeighbors(n_neighbors=2, metric='euclidean').fit(X_qut_s)
    qut_dist = nn.kneighbors(X_qut_s)[0][:, 1]
    
    # Probe to QUT distances
    nn1 = NearestNeighbors(n_neighbors=1, metric='euclidean').fit(X_qut_s)
    probe_dist = nn1.kneighbors(X_probe_s)[0].flatten()
    
    qut_median = np.median(qut_dist)
    qut_std = np.std(qut_dist)
    qut_p99 = np.percentile(qut_dist, 99)
    
    results = []
    for idx, (pkg, dist) in enumerate(zip(probe_df['package_name'], probe_dist)):
        std_above = (dist - qut_median) / qut_std if qut_std > 0 else 0
        pctl = stats.percentileofscore(qut_dist, dist)
        results.append({'package': pkg, 'nn_dist': dist, 'std_above': std_above, 
                       'percentile': pctl, 'label': probe_df.iloc[idx]['label']})
    
    return pd.DataFrame(results), {'median': qut_median, 'std': qut_std, 'p99': qut_p99}

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("\n" + "#" * 70)
    print("#  OOD CHECK - NO PATTERN FEATURES (26 features only)")
    print("#" * 70)
    
    qut_df = load_qut_dataset()
    pypi_rows, npm_rows = load_probe_data()
    
    # Fit scaler on QUT
    available = [f for f in FEATURES if f in qut_df.columns]
    X_qut = qut_df[available].apply(pd.to_numeric, errors='coerce').fillna(0).values
    scaler = StandardScaler().fit(X_qut)
    
    # Range checks
    print("\n" + "=" * 70)
    print("PER-FEATURE RANGE CHECK")
    print("=" * 70)
    
    _, pypi_summary = per_feature_range_check(qut_df, pypi_rows, "PyPI")
    _, npm_summary = per_feature_range_check(qut_df, npm_rows, "npm")
    
    print(f"\n{'Package':<45} {'In':>5} {'Out':>5} {'%In':>7}")
    print("-" * 65)
    print("PyPI:")
    for _, r in pypi_summary.iterrows():
        print(f"  {r['package']:<43} {int(r['in_range']):>5} {int(r['out_of_range']):>5} {r['pct_in']:>6.1f}%")
    print("\nnpm:")
    for _, r in npm_summary.iterrows():
        print(f"  {r['package']:<43} {int(r['in_range']):>5} {int(r['out_of_range']):>5} {r['pct_in']:>6.1f}%")
    
    # NN distances
    print("\n" + "=" * 70)
    print("NEAREST-NEIGHBOR DISTANCES")
    print("=" * 70)
    
    pypi_nn, qut_stats = nn_distance_check(qut_df, pypi_rows, "PyPI", scaler)
    npm_nn, _ = nn_distance_check(qut_df, npm_rows, "npm", scaler)
    
    print(f"\nQUT-DV25 internal: median={qut_stats['median']:.4f}, std={qut_stats['std']:.4f}, 99th={qut_stats['p99']:.4f}")
    
    print(f"\n{'Package':<45} {'Dist':>8} {'StdAbv':>8} {'Pctl':>7}")
    print("-" * 70)
    print("PyPI:")
    for _, r in pypi_nn.iterrows():
        print(f"  {r['package']:<43} {r['nn_dist']:>8.2f} {r['std_above']:>8.1f} {r['percentile']:>6.1f}%")
    print("\nnpm:")
    for _, r in npm_nn.iterrows():
        print(f"  {r['package']:<43} {r['nn_dist']:>8.2f} {r['std_above']:>8.1f} {r['percentile']:>6.1f}%")
    
    # Summary comparison
    print("\n" + "=" * 70)
    print("SUMMARY COMPARISON (No Pattern Features)")
    print("=" * 70)
    
    pypi_mean_dist = pypi_nn['nn_dist'].mean()
    npm_mean_dist = npm_nn['nn_dist'].mean()
    pypi_mean_pctl = pypi_nn['percentile'].mean()
    npm_mean_pctl = npm_nn['percentile'].mean()
    pypi_in_range = pypi_summary['pct_in'].mean()
    npm_in_range = npm_summary['pct_in'].mean()
    
    print(f"\n{'Metric':<45} {'PyPI':>12} {'npm':>12}")
    print("-" * 70)
    print(f"{'Mean NN distance:':<45} {pypi_mean_dist:>12.4f} {npm_mean_dist:>12.4f}")
    print(f"{'Mean percentile:':<45} {pypi_mean_pctl:>11.1f}% {npm_mean_pctl:>11.1f}%")
    print(f"{'Avg % features in range:':<45} {pypi_in_range:>11.1f}% {npm_in_range:>11.1f}%")
    print(f"{'QUT-DV25 99th percentile NN:':<45} {qut_stats['p99']:>12.4f} {'(threshold)':>12}")
    
    # Interpretation
    print("\n" + "=" * 70)
    print("INTERPRETATION")
    print("=" * 70)
    
    if pypi_mean_pctl < 95:
        pypi_status = "IN-DISTRIBUTION"
    elif pypi_mean_pctl < 99:
        pypi_status = "BORDERLINE"
    else:
        pypi_status = "OUT-OF-DISTRIBUTION"
    
    if npm_mean_pctl < 95:
        npm_status = "IN-DISTRIBUTION"
    elif npm_mean_pctl < 99:
        npm_status = "BORDERLINE"
    else:
        npm_status = "OUT-OF-DISTRIBUTION"
    
    print(f"""
    Without pattern features (using only 26 core features):
    
    PyPI: {pypi_status}
      - Mean NN distance: {pypi_mean_dist:.4f}
      - Mean percentile: {pypi_mean_pctl:.1f}%
      - Feature compliance: {pypi_in_range:.1f}%
    
    npm: {npm_status}
      - Mean NN distance: {npm_mean_dist:.4f}
      - Mean percentile: {npm_mean_pctl:.1f}%
      - Feature compliance: {npm_in_range:.1f}%
    
    QUT-DV25 reference:
      - 99th percentile threshold: {qut_stats['p99']:.4f}
    """)
    
    if pypi_mean_dist < npm_mean_dist:
        ratio = npm_mean_dist / pypi_mean_dist
        print(f"    PyPI is {ratio:.1f}x closer to QUT-DV25 than npm.")
    
    # Save
    OUTPUT_DIR.mkdir(exist_ok=True)
    pypi_nn.to_csv(OUTPUT_DIR / "pypi_nn_no_patterns.csv", index=False)
    npm_nn.to_csv(OUTPUT_DIR / "npm_nn_no_patterns.csv", index=False)
    
    return {'pypi_mean_dist': pypi_mean_dist, 'npm_mean_dist': npm_mean_dist,
            'pypi_pctl': pypi_mean_pctl, 'npm_pctl': npm_mean_pctl}

if __name__ == "__main__":
    main()
