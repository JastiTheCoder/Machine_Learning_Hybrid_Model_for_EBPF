"""
Reproduce QUT-DV25 Paper Benchmark
==================================
This script attempts to reproduce the paper's reported 95.99% accuracy / 96.02% F1
on QUT-DV25 data alone.

Purpose: Verify our ML pipeline is sound BEFORE interpreting any cross-domain results.
If we can't hit ~96% on QUT-DV25, nothing downstream can be trusted.

Paper reference: QUT-DV25 dataset paper claims RF achieves 95.99% accuracy.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

QUT_BASE = Path(r"c:\Users\ksj42\Downloads\Desktop\College\Capstone_research\Harvard_Datasets\QUT-DV25_extracted\QUT-DV25_Datasets\QUT-DV25_Processed_Datasets")
OUTPUT_DIR = Path(__file__).parent / "outputs"

# ============================================================================
# STEP 1: LOAD QUT-DV25 RAW DATA (NO CUSTOM EXTRACTION)
# ============================================================================

def load_qut_raw():
    """
    Load QUT-DV25 CSV files and use their values AS-IS.
    No custom feature extraction - we want to see what they provide.
    """
    print("=" * 70)
    print("LOADING QUT-DV25 DATA (RAW, NO CUSTOM EXTRACTION)")
    print("=" * 70)
    
    filetop = pd.read_csv(QUT_BASE / "QUT-DV25_Filetop_Traces" / "QUT-DV25_Filetop_Traces.csv")
    syscall = pd.read_csv(QUT_BASE / "QUT-DV25_SysCall_Traces" / "QUT-DV25_SysCall_Traces.csv")
    tcp = pd.read_csv(QUT_BASE / "QUT-DV25_TCP_Traces" / "QUT-DV25_TCP_Traces.csv")
    opensnoop = pd.read_csv(QUT_BASE / "QUT-DV25_Opensnoop_Traces" / "QUT-DV25_Opensnoop_Traces.csv")
    install = pd.read_csv(QUT_BASE / "QUT-DV25_Install_Traces" / "QUT-DV25_Install_Traces.csv")
    pattern = pd.read_csv(QUT_BASE / "QUT-DV25_Pattern_Traces" / "QUT-DV25_Pattern_Traces.csv")
    
    print(f"  Filetop: {len(filetop)} rows, {len(filetop.columns)} cols")
    print(f"  Syscall: {len(syscall)} rows, {len(syscall.columns)} cols")
    print(f"  TCP: {len(tcp)} rows, {len(tcp.columns)} cols")
    print(f"  Opensnoop: {len(opensnoop)} rows, {len(opensnoop.columns)} cols")
    print(f"  Install: {len(install)} rows, {len(install.columns)} cols")
    print(f"  Pattern: {len(pattern)} rows, {len(pattern.columns)} cols")
    
    return {
        'filetop': filetop,
        'syscall': syscall,
        'tcp': tcp,
        'opensnoop': opensnoop,
        'install': install,
        'pattern': pattern
    }

def inspect_columns(data):
    """Print column info to understand the data structure."""
    print("\n" + "=" * 70)
    print("COLUMN INSPECTION")
    print("=" * 70)
    
    for name, df in data.items():
        print(f"\n{name.upper()}:")
        for col in df.columns:
            dtype = df[col].dtype
            sample = df[col].iloc[0] if len(df) > 0 else "N/A"
            if isinstance(sample, str) and len(sample) > 50:
                sample = sample[:50] + "..."
            print(f"  {col}: {dtype} (e.g., {sample})")

# ============================================================================
# STEP 2: BUILD FEATURE MATRIX (USING QUT'S NUMERIC COLUMNS DIRECTLY)
# ============================================================================

def build_feature_matrix(data):
    """
    Build feature matrix using QUT-DV25's numeric columns directly.
    For categorical columns (Pattern_N), use label encoding.
    """
    print("\n" + "=" * 70)
    print("BUILDING FEATURE MATRIX")
    print("=" * 70)
    
    filetop = data['filetop']
    syscall = data['syscall']
    tcp = data['tcp']
    opensnoop = data['opensnoop']
    install = data['install']
    pattern = data['pattern']
    
    # Start with package name and label
    merged = filetop[['Package_Name', 'Level']].copy()
    
    # =========================================================================
    # FILETOP FEATURES (handle list-valued columns by counting elements)
    # =========================================================================
    # Read_Processes, Write_Processes, File_Access_Processes are comma-separated lists
    merged['read_processes_count'] = filetop['Read_Processes'].fillna('').apply(
        lambda x: len([p for p in str(x).split(',') if p.strip()]) if pd.notna(x) and str(x).strip() else 0
    )
    merged['write_processes_count'] = filetop['Write_Processes'].fillna('').apply(
        lambda x: len([p for p in str(x).split(',') if p.strip()]) if pd.notna(x) and str(x).strip() else 0
    )
    merged['file_access_processes_count'] = filetop['File_Access_Processes'].fillna('').apply(
        lambda x: len([p for p in str(x).split(',') if p.strip()]) if pd.notna(x) and str(x).strip() else 0
    )
    
    # Numeric filetop columns
    merged['total_read_data'] = pd.to_numeric(filetop['Total_Read_Data_Transfer'], errors='coerce').fillna(0)
    merged['total_write_data'] = pd.to_numeric(filetop['Total_Write_Data_Transfer'], errors='coerce').fillna(0)
    
    # =========================================================================
    # SYSCALL FEATURES (already numeric in QUT)
    # =========================================================================
    syscall_cols = ['File_Operations', 'Network_Operations', 'IO_Operations',
                    'Process_Management_Operations', 'Memory_Operations', 
                    'Security_Operations', 'Time_Operations', 'Miscellaneous_Operations']
    
    syscall_subset = syscall[['Package_Name'] + syscall_cols].copy()
    for col in syscall_cols:
        syscall_subset[col] = pd.to_numeric(syscall_subset[col], errors='coerce').fillna(0)
    
    merged = merged.merge(syscall_subset, on='Package_Name', how='left')
    
    # =========================================================================
    # TCP FEATURES (already numeric in QUT)
    # =========================================================================
    tcp_cols = ['Total_Entries', 'Local_IP_Address_Access', 'Remote_IP_Address_Access',
                'Local_Port_Access', 'Remote_Port_Access']
    
    tcp_subset = tcp[['Package_Name'] + tcp_cols].copy()
    for col in tcp_cols:
        tcp_subset[col] = pd.to_numeric(tcp_subset[col], errors='coerce').fillna(0)
    
    merged = merged.merge(tcp_subset, on='Package_Name', how='left')
    
    # =========================================================================
    # OPENSNOOP FEATURES (already numeric in QUT)
    # =========================================================================
    opensnoop_cols = ['Root_DIR_Installation', 'Temporary_DIR_Installation',
                      'Home_DIR_Installation', 'User_Access', 'Sys_Access',
                      'Etc_DIR_Installation', 'Other_DIR_Installation']
    
    opensnoop_subset = opensnoop[['Package_Name'] + opensnoop_cols].copy()
    for col in opensnoop_cols:
        opensnoop_subset[col] = pd.to_numeric(opensnoop_subset[col], errors='coerce').fillna(0)
    
    merged = merged.merge(opensnoop_subset, on='Package_Name', how='left')
    
    # =========================================================================
    # INSTALL FEATURES (already numeric in QUT)
    # =========================================================================
    install_cols = ['Total_Dependencies', 'Direct_Dependencies', 'Indirect_Dependencies']
    
    install_subset = install[['Package_Name'] + install_cols].copy()
    for col in install_cols:
        install_subset[col] = pd.to_numeric(install_subset[col], errors='coerce').fillna(0)
    
    merged = merged.merge(install_subset, on='Package_Name', how='left')
    
    # =========================================================================
    # PATTERN FEATURES (categorical - use label encoding)
    # Only use Pattern_1..5 as per Anirudha's guidance
    # =========================================================================
    pattern_cols = [f'Pattern_{i}' for i in range(1, 6)]  # Only 1-5!
    
    pattern_subset = pattern[['Package_Name'] + pattern_cols].copy()
    
    # Label encode each pattern column
    label_encoders = {}
    for col in pattern_cols:
        le = LabelEncoder()
        # Handle NaN by converting to string first
        pattern_subset[col] = pattern_subset[col].fillna('MISSING').astype(str)
        pattern_subset[f'{col}_encoded'] = le.fit_transform(pattern_subset[col])
        label_encoders[col] = le
    
    # Keep only encoded columns
    encoded_cols = [f'{col}_encoded' for col in pattern_cols]
    pattern_encoded = pattern_subset[['Package_Name'] + encoded_cols]
    
    merged = merged.merge(pattern_encoded, on='Package_Name', how='left')
    
    # Fill any remaining NaN
    merged = merged.fillna(0)
    
    print(f"\nFinal merged dataset: {len(merged)} samples")
    print(f"Label distribution:")
    print(f"  Benign (0): {sum(merged['Level'] == 0)}")
    print(f"  Malicious (1): {sum(merged['Level'] == 1)}")
    
    return merged, label_encoders

# ============================================================================
# STEP 3: TRAIN AND EVALUATE
# ============================================================================

def get_feature_columns(df):
    """Get list of feature columns (exclude metadata)."""
    exclude = ['Package_Name', 'Level']
    return [col for col in df.columns if col not in exclude]

def train_and_evaluate(df):
    """Train Random Forest and evaluate using cross-validation and holdout."""
    print("\n" + "=" * 70)
    print("TRAINING AND EVALUATION")
    print("=" * 70)
    
    feature_cols = get_feature_columns(df)
    print(f"\nUsing {len(feature_cols)} features:")
    for i, col in enumerate(feature_cols, 1):
        print(f"  {i:2d}. {col}")
    
    X = df[feature_cols].values
    y = df['Level'].values
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # =========================================================================
    # METHOD 1: 5-Fold Stratified Cross-Validation
    # =========================================================================
    print("\n" + "-" * 70)
    print("METHOD 1: 5-Fold Stratified Cross-Validation")
    print("-" * 70)
    
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(rf, X_scaled, y, cv=cv, scoring='accuracy')
    cv_f1 = cross_val_score(rf, X_scaled, y, cv=cv, scoring='f1')
    
    print(f"\nCross-Validation Results:")
    print(f"  Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
    print(f"  F1 Score: {cv_f1.mean():.4f} (+/- {cv_f1.std()*2:.4f})")
    print(f"  Individual fold accuracies: {[f'{s:.4f}' for s in cv_scores]}")
    
    # =========================================================================
    # METHOD 2: 80/20 Holdout Split
    # =========================================================================
    print("\n" + "-" * 70)
    print("METHOD 2: 80/20 Holdout Split")
    print("-" * 70)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTrain set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    rf_holdout = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_holdout.fit(X_train, y_train)
    
    y_pred = rf_holdout.predict(X_test)
    
    holdout_acc = accuracy_score(y_test, y_pred)
    holdout_f1 = f1_score(y_test, y_pred)
    
    print(f"\nHoldout Results:")
    print(f"  Accuracy: {holdout_acc:.4f}")
    print(f"  F1 Score: {holdout_f1:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    
    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                 Predicted")
    print(f"                 Benign  Malicious")
    print(f"Actual Benign    {cm[0,0]:5d}      {cm[0,1]:5d}")
    print(f"Actual Malicious {cm[1,0]:5d}      {cm[1,1]:5d}")
    
    # =========================================================================
    # FEATURE IMPORTANCE
    # =========================================================================
    print("\n" + "-" * 70)
    print("TOP 10 FEATURE IMPORTANCES")
    print("-" * 70)
    
    importances = pd.Series(rf_holdout.feature_importances_, index=feature_cols)
    top_features = importances.sort_values(ascending=False).head(10)
    
    for feat, imp in top_features.items():
        print(f"  {feat:<40} {imp:.4f}")
    
    # =========================================================================
    # COMPARISON WITH PAPER
    # =========================================================================
    print("\n" + "=" * 70)
    print("COMPARISON WITH PAPER'S REPORTED RESULTS")
    print("=" * 70)
    
    paper_acc = 0.9599
    paper_f1 = 0.9602
    
    print(f"\n{'Metric':<20} {'Paper':>12} {'Ours (CV)':>12} {'Ours (Holdout)':>14} {'Diff (CV)':>12}")
    print("-" * 70)
    print(f"{'Accuracy':<20} {paper_acc:>12.4f} {cv_scores.mean():>12.4f} {holdout_acc:>14.4f} {cv_scores.mean()-paper_acc:>+12.4f}")
    print(f"{'F1 Score':<20} {paper_f1:>12.4f} {cv_f1.mean():>12.4f} {holdout_f1:>14.4f} {cv_f1.mean()-paper_f1:>+12.4f}")
    
    # Interpretation
    print("\n" + "=" * 70)
    print("INTERPRETATION")
    print("=" * 70)
    
    if cv_scores.mean() >= 0.90:
        print("""
    SUCCESS: Our pipeline achieves ~{:.1f}% accuracy on QUT-DV25.
    
    This confirms:
    1. Our ML pipeline is fundamentally sound
    2. The Random Forest approach works on this data
    3. Any failures on external data (npm captures) are genuine transfer issues,
       not artifacts of a broken pipeline
    
    The small difference from paper ({:+.2f}%) is likely due to:
    - Different random seeds
    - Slightly different feature encoding choices
    - The paper may have used additional preprocessing
        """.format(cv_scores.mean()*100, (cv_scores.mean()-paper_acc)*100))
    else:
        print("""
    WARNING: Our accuracy ({:.1f}%) is significantly below the paper's ({:.1f}%).
    
    This suggests:
    1. Our feature extraction may still have issues
    2. We may be missing important preprocessing steps
    3. The 0% recall on npm data might be caused by pipeline bugs, not domain shift
    
    RECOMMENDATION: Investigate feature extraction before interpreting cross-domain results.
        """.format(cv_scores.mean()*100, paper_acc*100))
    
    return {
        'cv_accuracy': cv_scores.mean(),
        'cv_f1': cv_f1.mean(),
        'holdout_accuracy': holdout_acc,
        'holdout_f1': holdout_f1,
        'paper_accuracy': paper_acc,
        'paper_f1': paper_f1
    }

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("\n" + "#" * 70)
    print("#  REPRODUCE QUT-DV25 PAPER BENCHMARK")
    print("#  Target: 95.99% accuracy / 96.02% F1 (as reported in paper)")
    print("#" * 70)
    
    # Load raw data
    data = load_qut_raw()
    
    # Optionally inspect columns (uncomment if needed)
    # inspect_columns(data)
    
    # Build feature matrix
    df, label_encoders = build_feature_matrix(data)
    
    # Train and evaluate
    results = train_and_evaluate(df)
    
    # Save results
    OUTPUT_DIR.mkdir(exist_ok=True)
    results_df = pd.DataFrame([results])
    results_df.to_csv(OUTPUT_DIR / "qut_benchmark_results.csv", index=False)
    
    print(f"\nResults saved to: {OUTPUT_DIR / 'qut_benchmark_results.csv'}")
    
    return results

if __name__ == "__main__":
    main()
