"""
Out-of-Distribution Check - COUNT VS COUNT
===========================================
Compare our captures against QUT's ACTUAL frequency counts (not label-encoded).

QUT Reference (196 packages):
- Extracted from raw strace with same algorithm as our monitor
- p1_count median: ~2040 (IQR 1458-3351)
- Our PyPI at ~1806 should be ~43rd percentile
- Our npm should be 72nd-93rd percentile
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

SCRIPT_DIR = Path(__file__).parent
QUT_REF = SCRIPT_DIR / "qut-reference-196.csv"
CORPUS_17 = SCRIPT_DIR / "corpus-17-schema2.csv"
PYPI_SAMPLE = SCRIPT_DIR / "pypi-sample-3-schema2.csv"
OUTPUT_DIR = SCRIPT_DIR / "outputs"

# Pattern count features (now comparable!)
PATTERN_FEATURES = ['p1_count', 'p2_count', 'p3_count', 'p4_count', 'p5_count']

# ============================================================================
# LOAD DATA
# ============================================================================

def load_qut_reference():
    """Load QUT reference with actual frequency counts."""
    print("=" * 70)
    print("LOADING QUT REFERENCE (196 packages, actual counts)")
    print("=" * 70)
    
    df = pd.read_csv(QUT_REF, encoding='utf-8-sig')
    
    print(f"  Samples: {len(df)}")
    print(f"  Benign: {sum(df['label'] == 0)}")
    print(f"  Malicious: {sum(df['label'] == 1)}")
    
    # Show p1_count distribution
    p1 = df['p1_count']
    print(f"\n  p1_count distribution:")
    print(f"    Min: {p1.min()}")
    print(f"    25th: {p1.quantile(0.25):.0f}")
    print(f"    Median: {p1.median():.0f}")
    print(f"    75th: {p1.quantile(0.75):.0f}")
    print(f"    Max: {p1.max()}")
    
    return df

def load_probe_data():
    """Load PyPI and npm probe data."""
    print("\n" + "=" * 70)
    print("LOADING PROBE DATA")
    print("=" * 70)
    
    corpus = pd.read_csv(CORPUS_17, encoding='utf-8-sig')
    
    pypi_mask = corpus['package_name'].str.contains('pypi', case=False, na=False)
    pypi_rows = corpus[pypi_mask].copy()
    npm_rows = corpus[~pypi_mask].copy()
    
    print(f"  PyPI: {len(pypi_rows)} rows")
    print(f"  npm: {len(npm_rows)} rows")
    
    # Show our p1_count values
    print(f"\n  Our p1_count values:")
    print(f"    PyPI: {pypi_rows['p1_count'].tolist()}")
    print(f"    npm range: {npm_rows['p1_count'].min()} - {npm_rows['p1_count'].max()}")
    
    return pypi_rows, npm_rows

# ============================================================================
# ANALYSIS
# ============================================================================

def per_feature_percentile(qut_df, probe_df, features, name):
    """Calculate where each probe value falls in QUT's distribution."""
    print(f"\n{'='*70}")
    print(f"PERCENTILE ANALYSIS: {name}")
    print("="*70)
    
    results = []
    
    for feat in features:
        if feat not in qut_df.columns or feat not in probe_df.columns:
            continue
        
        qut_vals = pd.to_numeric(qut_df[feat], errors='coerce').fillna(0)
        probe_vals = pd.to_numeric(probe_df[feat], errors='coerce').fillna(0)
        
        qut_median = qut_vals.median()
        qut_p25 = qut_vals.quantile(0.25)
        qut_p75 = qut_vals.quantile(0.75)
        
        for idx, val in enumerate(probe_vals):
            pctl = stats.percentileofscore(qut_vals, val)
            
            if pctl < 25:
                status = "LOW"
            elif pctl > 75:
                status = "HIGH"
            else:
                status = "NORMAL (IQR)"
            
            results.append({
                'package': probe_df.iloc[idx]['package_name'],
                'feature': feat,
                'value': val,
                'percentile': pctl,
                'qut_median': qut_median,
                'status': status
            })
    
    df = pd.DataFrame(results)
    
    # Print summary per package
    print(f"\n{'Package':<45} {'p1_count':>10} {'p1_pctl':>10} {'Avg_pctl':>10}")
    print("-" * 80)
    
    for pkg in probe_df['package_name'].unique():
        pkg_data = df[df['package'] == pkg]
        p1_row = pkg_data[pkg_data['feature'] == 'p1_count'].iloc[0]
        avg_pctl = pkg_data['percentile'].mean()
        print(f"{pkg:<45} {p1_row['value']:>10.0f} {p1_row['percentile']:>9.1f}% {avg_pctl:>9.1f}%")
    
    return df

def nn_distance_check(qut_df, probe_df, name, scaler):
    """Compute NN distances using pattern count features."""
    print(f"\n{'='*70}")
    print(f"NN DISTANCE CHECK: {name}")
    print("="*70)
    
    available = [f for f in PATTERN_FEATURES if f in qut_df.columns and f in probe_df.columns]
    
    X_qut = qut_df[available].apply(pd.to_numeric, errors='coerce').fillna(0).values
    X_probe = probe_df[available].apply(pd.to_numeric, errors='coerce').fillna(0).values
    
    X_qut_s = scaler.transform(X_qut)
    X_probe_s = scaler.transform(X_probe)
    
    # QUT internal distances
    nn = NearestNeighbors(n_neighbors=2, metric='euclidean').fit(X_qut_s)
    qut_dist = nn.kneighbors(X_qut_s)[0][:, 1]
    
    # Probe to QUT
    nn1 = NearestNeighbors(n_neighbors=1, metric='euclidean').fit(X_qut_s)
    probe_dist = nn1.kneighbors(X_probe_s)[0].flatten()
    
    qut_median = np.median(qut_dist)
    qut_std = np.std(qut_dist)
    qut_p95 = np.percentile(qut_dist, 95)
    qut_p99 = np.percentile(qut_dist, 99)
    
    print(f"\nQUT-196 internal NN distances:")
    print(f"  Median: {qut_median:.4f}")
    print(f"  Std: {qut_std:.4f}")
    print(f"  95th: {qut_p95:.4f}")
    print(f"  99th: {qut_p99:.4f}")
    
    results = []
    print(f"\n{'Package':<45} {'NN_Dist':>10} {'Pctl':>10} {'Status':>15}")
    print("-" * 85)
    
    for idx, (pkg, dist) in enumerate(zip(probe_df['package_name'], probe_dist)):
        pctl = stats.percentileofscore(qut_dist, dist)
        
        if pctl < 95:
            status = "IN-DISTRIBUTION"
        elif pctl < 99:
            status = "BORDERLINE"
        else:
            status = "OOD"
        
        results.append({
            'package': pkg,
            'nn_dist': dist,
            'percentile': pctl,
            'status': status,
            'label': probe_df.iloc[idx]['label']
        })
        
        print(f"{pkg:<45} {dist:>10.4f} {pctl:>9.1f}% {status:>15}")
    
    return pd.DataFrame(results), {'median': qut_median, 'std': qut_std, 'p95': qut_p95, 'p99': qut_p99}

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("\n" + "#" * 70)
    print("#  OOD CHECK - COUNT VS COUNT (Same Algorithm)")
    print("#  Using QUT Reference with ACTUAL frequency counts")
    print("#" * 70)
    
    qut_df = load_qut_reference()
    pypi_rows, npm_rows = load_probe_data()
    
    # Fit scaler on QUT reference
    available = [f for f in PATTERN_FEATURES if f in qut_df.columns]
    X_qut = qut_df[available].apply(pd.to_numeric, errors='coerce').fillna(0).values
    scaler = StandardScaler().fit(X_qut)
    
    # Percentile analysis
    pypi_pctl = per_feature_percentile(qut_df, pypi_rows, PATTERN_FEATURES, "PyPI PROBE")
    npm_pctl = per_feature_percentile(qut_df, npm_rows, PATTERN_FEATURES, "npm CONTROL")
    
    # NN distance check
    pypi_nn, qut_stats = nn_distance_check(qut_df, pypi_rows, "PyPI PROBE", scaler)
    npm_nn, _ = nn_distance_check(qut_df, npm_rows, "npm CONTROL", scaler)
    
    # Summary
    print("\n" + "=" * 70)
    print("FINAL SUMMARY - COUNT VS COUNT")
    print("=" * 70)
    
    pypi_mean_pctl = pypi_pctl['percentile'].mean()
    npm_mean_pctl = npm_pctl['percentile'].mean()
    
    pypi_mean_nn = pypi_nn['nn_dist'].mean()
    npm_mean_nn = npm_nn['nn_dist'].mean()
    
    pypi_nn_pctl = pypi_nn['percentile'].mean()
    npm_nn_pctl = npm_nn['percentile'].mean()
    
    print(f"\n{'Metric':<45} {'PyPI (3)':>12} {'npm (14)':>12}")
    print("-" * 70)
    print(f"{'Mean feature percentile:':<45} {pypi_mean_pctl:>11.1f}% {npm_mean_pctl:>11.1f}%")
    print(f"{'Mean NN distance:':<45} {pypi_mean_nn:>12.4f} {npm_mean_nn:>12.4f}")
    print(f"{'Mean NN percentile:':<45} {pypi_nn_pctl:>11.1f}% {npm_nn_pctl:>11.1f}%")
    print(f"{'QUT-196 95th pctl threshold:':<45} {qut_stats['p95']:>12.4f}")
    print(f"{'QUT-196 99th pctl threshold:':<45} {qut_stats['p99']:>12.4f}")
    
    # Determine status
    pypi_in_dist = pypi_nn_pctl < 95
    npm_in_dist = npm_nn_pctl < 95
    
    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    
    print(f"""
    With COUNT vs COUNT comparison (same algorithm):
    
    PyPI: {"IN-DISTRIBUTION" if pypi_in_dist else "OUT-OF-DISTRIBUTION"}
      - Feature percentile: {pypi_mean_pctl:.1f}%
      - NN percentile: {pypi_nn_pctl:.1f}%
      - Mean NN distance: {pypi_mean_nn:.4f}
    
    npm: {"IN-DISTRIBUTION" if npm_in_dist else "OUT-OF-DISTRIBUTION"}
      - Feature percentile: {npm_mean_pctl:.1f}%
      - NN percentile: {npm_nn_pctl:.1f}%
      - Mean NN distance: {npm_mean_nn:.4f}
    """)
    
    if pypi_in_dist and npm_in_dist:
        print("""
    BOTH ecosystems are IN-DISTRIBUTION when using proper count-vs-count comparison.
    The 0% recall was NOT due to out-of-distribution data - it was due to the
    feature encoding mismatch (comparing counts to category codes).
        """)
    elif pypi_in_dist and not npm_in_dist:
        print("""
    PyPI is IN-DISTRIBUTION, npm is OUT-OF-DISTRIBUTION.
    The ecosystem shift hypothesis IS SUPPORTED.
    Model trained on PyPI (QUT) should work on PyPI captures, but not npm.
        """)
    elif not pypi_in_dist and npm_in_dist:
        print("""
    Unexpected: npm is closer than PyPI.
        """)
    else:
        print("""
    Both are OUT-OF-DISTRIBUTION. Methodological differences remain.
        """)
    
    # Save results
    OUTPUT_DIR.mkdir(exist_ok=True)
    pypi_nn.to_csv(OUTPUT_DIR / "pypi_nn_count_vs_count.csv", index=False)
    npm_nn.to_csv(OUTPUT_DIR / "npm_nn_count_vs_count.csv", index=False)
    
    print(f"\nResults saved to {OUTPUT_DIR}")
    
    return {'pypi_in_dist': pypi_in_dist, 'npm_in_dist': npm_in_dist,
            'pypi_nn_pctl': pypi_nn_pctl, 'npm_nn_pctl': npm_nn_pctl}

if __name__ == "__main__":
    main()
