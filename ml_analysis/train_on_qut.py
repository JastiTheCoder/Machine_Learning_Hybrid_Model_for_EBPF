"""
Cross-Domain Malware Detection: Train on QUT-DV25 (PyPI), Test on npm
======================================================================

SUPERSEDED - see QUT_RETIREMENT.md. Retained as reproducible evidence for the
failed transfer; do not extend or train new models with it.

This script trains an ML model on the QUT-DV25 PyPI dataset and evaluates
its ability to detect malicious npm packages.

Research Question: Can malware detection patterns learned from PyPI
transfer to npm package detection?

Answer: No. Both models scored 0% recall on malicious npm packages, with an
approximate ROC AUC of 0.08 (below the 0.50 random-guessing baseline). QUT's
malicious class is characterised by reduced process activity (median 5,171
syscalls vs 10,415 benign) while ours is characterised by increased activity,
so 9 of 37 features transfer with the wrong sign. Feature selection cannot
repair a sign inversion.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

QUT_BASE = Path(r"c:\Users\ksj42\Downloads\Desktop\College\Capstone_research\Harvard_Datasets\QUT-DV25_extracted\QUT-DV25_Datasets\QUT-DV25_Processed_Datasets")
NPM_SESSIONS = Path(__file__).parent / "outputs" / "sessions_flattened.csv"
OUTPUT_DIR = Path(__file__).parent / "outputs"

# ============================================================================
# STEP 1: LOAD QUT-DV25 DATASET
# ============================================================================

def load_qut_dataset():
    """Load and merge all QUT-DV25 CSV files."""
    print("Loading QUT-DV25 dataset...")
    
    # Load each trace file
    filetop = pd.read_csv(QUT_BASE / "QUT-DV25_Filetop_Traces" / "QUT-DV25_Filetop_Traces.csv")
    syscall = pd.read_csv(QUT_BASE / "QUT-DV25_SysCall_Traces" / "QUT-DV25_SysCall_Traces.csv")
    tcp = pd.read_csv(QUT_BASE / "QUT-DV25_TCP_Traces" / "QUT-DV25_TCP_Traces.csv")
    opensnoop = pd.read_csv(QUT_BASE / "QUT-DV25_Opensnoop_Traces" / "QUT-DV25_Opensnoop_Traces.csv")
    install = pd.read_csv(QUT_BASE / "QUT-DV25_Install_Traces" / "QUT-DV25_Install_Traces.csv")
    pattern = pd.read_csv(QUT_BASE / "QUT-DV25_Pattern_Traces" / "QUT-DV25_Pattern_Traces.csv")
    
    print(f"  Filetop: {len(filetop)} rows")
    print(f"  Syscall: {len(syscall)} rows")
    print(f"  TCP: {len(tcp)} rows")
    print(f"  Opensnoop: {len(opensnoop)} rows")
    print(f"  Install: {len(install)} rows")
    print(f"  Pattern: {len(pattern)} rows")
    
    # Merge on Package_Name
    merged = filetop[['Package_Name', 'Level']].copy()
    
    # Extract numeric features from filetop
    merged['ft_read_processes'] = pd.to_numeric(filetop['Read_Processes'].str.split(',').str.len(), errors='coerce').fillna(0)
    merged['ft_write_processes'] = pd.to_numeric(filetop['Write_Processes'].str.split(',').str.len(), errors='coerce').fillna(0)
    merged['ft_read_data_kb'] = pd.to_numeric(filetop['Total_Read_Data_Transfer'], errors='coerce').fillna(0) / 1024
    merged['ft_write_data_kb'] = pd.to_numeric(filetop['Total_Write_Data_Transfer'], errors='coerce').fillna(0) / 1024
    merged['ft_file_access_processes'] = pd.to_numeric(filetop['File_Access_Processes'].str.split(',').str.len(), errors='coerce').fillna(0)
    
    # Extract from syscall
    syscall_merged = syscall[['Package_Name', 'File_Operations', 'Network_Operations', 
                              'IO_Operations', 'Process_Management_Operations',
                              'Memory_Operations', 'Security_Operations', 'Time_Operations',
                              'Miscellaneous_Operations']].copy()
    merged = merged.merge(syscall_merged, on='Package_Name', how='left')
    merged['sc_file_ops'] = pd.to_numeric(merged['File_Operations'], errors='coerce').fillna(0)
    merged['sc_network_ops'] = pd.to_numeric(merged['Network_Operations'], errors='coerce').fillna(0)
    merged['sc_io_ops'] = pd.to_numeric(merged['IO_Operations'], errors='coerce').fillna(0)
    merged['sc_process_ops'] = pd.to_numeric(merged['Process_Management_Operations'], errors='coerce').fillna(0)
    merged['sc_security_ops'] = pd.to_numeric(merged['Security_Operations'], errors='coerce').fillna(0)
    merged['sc_time_ops'] = pd.to_numeric(merged['Time_Operations'], errors='coerce').fillna(0)
    merged['sc_unknown_ops'] = pd.to_numeric(merged['Miscellaneous_Operations'], errors='coerce').fillna(0)
    
    # Extract from TCP (actual column names from QUT dataset)
    tcp_merged = tcp[['Package_Name', 'Total_Entries', 'Local_IP_Address_Access',
                      'Remote_IP_Address_Access', 'Local_Port_Access', 'Remote_Port_Access']].copy()
    merged = merged.merge(tcp_merged, on='Package_Name', how='left')
    merged['tcp_state_transitions'] = pd.to_numeric(merged['Total_Entries'], errors='coerce').fillna(0)
    merged['tcp_local_ips'] = pd.to_numeric(merged['Local_IP_Address_Access'], errors='coerce').fillna(0)
    merged['tcp_remote_ips'] = pd.to_numeric(merged['Remote_IP_Address_Access'], errors='coerce').fillna(0)
    merged['tcp_local_ports'] = pd.to_numeric(merged['Local_Port_Access'], errors='coerce').fillna(0)
    merged['tcp_remote_ports'] = pd.to_numeric(merged['Remote_Port_Access'], errors='coerce').fillna(0)
    
    # Extract from opensnoop (directory access) - actual QUT column names
    opensnoop_cols = opensnoop[['Package_Name', 'Root_DIR_Installation', 'Temporary_DIR_Installation',
                                 'Home_DIR_Installation', 'User_Access', 'Sys_Access', 
                                 'Etc_DIR_Installation', 'Other_DIR_Installation']].copy()
    merged = merged.merge(opensnoop_cols, on='Package_Name', how='left')
    
    # Map opensnoop to our feature names
    merged['os_etc_dir'] = pd.to_numeric(merged['Etc_DIR_Installation'], errors='coerce').fillna(0)
    merged['os_home_dir'] = pd.to_numeric(merged['Home_DIR_Installation'], errors='coerce').fillna(0)
    merged['os_root_dir'] = pd.to_numeric(merged['Root_DIR_Installation'], errors='coerce').fillna(0)
    merged['os_sys_dir'] = pd.to_numeric(merged['Sys_Access'], errors='coerce').fillna(0)
    merged['os_temp_dir'] = pd.to_numeric(merged['Temporary_DIR_Installation'], errors='coerce').fillna(0)
    merged['os_user_dir'] = pd.to_numeric(merged['User_Access'], errors='coerce').fillna(0)
    merged['os_other_dir'] = pd.to_numeric(merged['Other_DIR_Installation'], errors='coerce').fillna(0)
    merged['os_ssh_aws_wallet'] = 0  # QUT doesn't have this specific feature
    
    # Extract from install
    install_merged = install[['Package_Name', 'Total_Dependencies', 'Direct_Dependencies',
                              'Indirect_Dependencies']].copy()
    merged = merged.merge(install_merged, on='Package_Name', how='left')
    merged['inst_total_deps'] = pd.to_numeric(merged['Total_Dependencies'], errors='coerce').fillna(0)
    merged['inst_direct_deps'] = pd.to_numeric(merged['Direct_Dependencies'], errors='coerce').fillna(0)
    merged['inst_indirect_deps'] = pd.to_numeric(merged['Indirect_Dependencies'], errors='coerce').fillna(0)
    
    # Extract from pattern - QUT patterns are strings, we'll derive features from them
    # Combine all pattern columns into one string per row for analysis
    pattern_cols = [f'Pattern_{i}' for i in range(1, 11)]
    pattern['all_patterns'] = pattern[pattern_cols].fillna('').apply(lambda x: ' '.join(x.astype(str)).lower(), axis=1)
    
    pattern_merged = pattern[['Package_Name']].copy()
    
    # Vectorized count of syscall patterns
    pattern_merged['pat_file_metadata'] = pattern['all_patterns'].str.count('fstat|newfstatat')
    pattern_merged['pat_read_data'] = pattern['all_patterns'].str.count('read')
    pattern_merged['pat_write_data'] = pattern['all_patterns'].str.count('write')
    pattern_merged['pat_socket_create'] = pattern['all_patterns'].str.count('socket')
    pattern_merged['pat_process_create'] = pattern['all_patterns'].str.count('fork|clone')
    pattern_merged['pat_memory_map'] = pattern['all_patterns'].str.count('mmap')
    pattern_merged['pat_fd_manage'] = pattern['all_patterns'].str.count('fcntl|dup')
    pattern_merged['pat_ipc'] = pattern['all_patterns'].str.count('pipe')
    pattern_merged['pat_file_lock'] = pattern['all_patterns'].str.count('flock')
    pattern_merged['pat_error_handle'] = pattern['all_patterns'].str.count('error')
    
    merged = merged.merge(pattern_merged, on='Package_Name', how='left')
    
    # Fill NaN pattern features
    for col in ['pat_file_metadata', 'pat_read_data', 'pat_write_data', 'pat_socket_create',
                'pat_process_create', 'pat_memory_map', 'pat_fd_manage', 'pat_ipc', 
                'pat_file_lock', 'pat_error_handle']:
        merged[col] = merged[col].fillna(0)
    
    # Rename label column
    merged['label'] = merged['Level']
    
    print(f"\nMerged QUT dataset: {len(merged)} samples")
    print(f"  Benign: {sum(merged['label'] == 0)}")
    print(f"  Malicious: {sum(merged['label'] == 1)}")
    
    return merged

# ============================================================================
# STEP 2: LOAD NPM TEST DATASET
# ============================================================================

def load_npm_dataset():
    """Load the npm sessions for testing."""
    print("\nLoading npm test dataset...")
    
    df = pd.read_csv(NPM_SESSIONS)
    
    # Convert label to numeric
    df['label_numeric'] = (df['label'] == 'malicious').astype(int)
    
    print(f"  Total: {len(df)} samples")
    print(f"  Benign: {sum(df['label_numeric'] == 0)}")
    print(f"  Malicious: {sum(df['label_numeric'] == 1)}")
    
    return df

# ============================================================================
# STEP 3: FEATURE ALIGNMENT
# ============================================================================

def get_common_features():
    """Get the list of features that exist in both datasets."""
    return [
        'ft_read_processes', 'ft_write_processes', 'ft_read_data_kb', 'ft_write_data_kb',
        'ft_file_access_processes',
        'inst_total_deps', 'inst_direct_deps', 'inst_indirect_deps',
        'os_etc_dir', 'os_home_dir', 'os_other_dir', 'os_root_dir', 
        'os_sys_dir', 'os_temp_dir', 'os_user_dir',
        'tcp_state_transitions', 'tcp_local_ips', 'tcp_remote_ips', 
        'tcp_local_ports', 'tcp_remote_ports',
        'sc_io_ops', 'sc_file_ops', 'sc_network_ops', 'sc_time_ops',
        'sc_security_ops', 'sc_process_ops', 'sc_unknown_ops',
        'pat_file_metadata', 'pat_read_data', 'pat_write_data',
        'pat_socket_create', 'pat_process_create', 'pat_memory_map',
        'pat_fd_manage', 'pat_ipc', 'pat_file_lock', 'pat_error_handle'
    ]

def prepare_features(df, features):
    """Prepare feature matrix, filling missing columns with 0."""
    X = pd.DataFrame()
    for feat in features:
        if feat in df.columns:
            X[feat] = pd.to_numeric(df[feat], errors='coerce').fillna(0)
        else:
            X[feat] = 0
    return X.values

# ============================================================================
# STEP 4: TRAIN AND EVALUATE
# ============================================================================

def train_and_evaluate():
    """Train on QUT, test on npm."""
    
    # Load datasets
    qut_df = load_qut_dataset()
    npm_df = load_npm_dataset()
    
    # Get common features
    features = get_common_features()
    print(f"\nUsing {len(features)} features for training")
    
    # Prepare data
    X_train = prepare_features(qut_df, features)
    y_train = qut_df['label'].values
    
    X_test = prepare_features(npm_df, features)
    y_test = npm_df['label_numeric'].values
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print(f"\nTraining data: {X_train.shape[0]} samples")
    print(f"Test data: {X_test.shape[0]} samples")
    
    # =========================================================================
    # TRAIN RANDOM FOREST
    # =========================================================================
    print("\n" + "="*70)
    print("RANDOM FOREST CLASSIFIER")
    print("="*70)
    
    rf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10, n_jobs=-1)
    print("Training Random Forest on QUT-DV25 (14,271 samples)...")
    rf.fit(X_train_scaled, y_train)
    print("Training complete!")
    
    # Predict on npm
    print("\nTesting on npm sessions...")
    rf_pred = rf.predict(X_test_scaled)
    rf_prob = rf.predict_proba(X_test_scaled)[:, 1]
    
    rf_acc = accuracy_score(y_test, rf_pred)
    print(f"\nRandom Forest Accuracy on npm: {rf_acc:.2%}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, rf_pred, target_names=['Benign', 'Malicious']))
    
    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, rf_pred)
    print(f"                 Predicted")
    print(f"                 Benign  Malicious")
    print(f"Actual Benign      {cm[0,0]:3d}      {cm[0,1]:3d}")
    print(f"Actual Malicious   {cm[1,0]:3d}      {cm[1,1]:3d}")
    
    # =========================================================================
    # TRAIN XGBOOST
    # =========================================================================
    print("\n" + "="*70)
    print("XGBOOST CLASSIFIER")
    print("="*70)
    
    xgb_model = xgb.XGBClassifier(n_estimators=100, random_state=42, max_depth=6, 
                                   use_label_encoder=False, eval_metric='logloss', n_jobs=-1)
    print("Training XGBoost on QUT-DV25...")
    xgb_model.fit(X_train_scaled, y_train)
    print("Training complete!")
    
    # Predict on npm
    xgb_pred = xgb_model.predict(X_test_scaled)
    xgb_prob = xgb_model.predict_proba(X_test_scaled)[:, 1]
    
    xgb_acc = accuracy_score(y_test, xgb_pred)
    print(f"\nXGBoost Accuracy on npm: {xgb_acc:.2%}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, xgb_pred, target_names=['Benign', 'Malicious']))
    
    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, xgb_pred)
    print(f"                 Predicted")
    print(f"                 Benign  Malicious")
    print(f"Actual Benign      {cm[0,0]:3d}      {cm[0,1]:3d}")
    print(f"Actual Malicious   {cm[1,0]:3d}      {cm[1,1]:3d}")
    
    # =========================================================================
    # DETAILED PREDICTIONS
    # =========================================================================
    print("\n" + "="*70)
    print("DETAILED PREDICTIONS FOR EACH NPM PACKAGE")
    print("="*70)
    
    results = npm_df[['package_name', 'label']].copy()
    results['rf_prediction'] = ['malicious' if p == 1 else 'benign' for p in rf_pred]
    results['rf_confidence'] = rf_prob
    results['xgb_prediction'] = ['malicious' if p == 1 else 'benign' for p in xgb_pred]
    results['xgb_confidence'] = xgb_prob
    results['correct_rf'] = results['label'] == results['rf_prediction']
    results['correct_xgb'] = results['label'] == results['xgb_prediction']
    
    print(f"\n{'Package':<30} {'Actual':<12} {'RF Pred':<12} {'RF Conf':<10} {'XGB Pred':<12} {'XGB Conf':<10}")
    print("-" * 96)
    for _, row in results.iterrows():
        rf_mark = "OK" if row['correct_rf'] else "MISS"
        xgb_mark = "OK" if row['correct_xgb'] else "MISS"
        print(f"{row['package_name']:<30} {row['label']:<12} {row['rf_prediction']:<12} {row['rf_confidence']:.2%} {rf_mark:<6} {row['xgb_prediction']:<12} {row['xgb_confidence']:.2%} {xgb_mark}")
    
    # Save results
    results.to_csv(OUTPUT_DIR / "qut_trained_npm_predictions.csv", index=False)
    print(f"\nResults saved to: {OUTPUT_DIR / 'qut_trained_npm_predictions.csv'}")
    
    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "="*70)
    print("SUMMARY: CROSS-DOMAIN MALWARE DETECTION")
    print("="*70)
    print(f"""
Training Dataset: QUT-DV25 (PyPI)
  - Samples: {len(qut_df)}
  - Benign: {sum(y_train == 0)}
  - Malicious: {sum(y_train == 1)}

Test Dataset: npm sessions (Aniruddha's captures)
  - Samples: {len(npm_df)}
  - Benign: {sum(y_test == 0)}
  - Malicious: {sum(y_test == 1)}

Results:
  - Random Forest Accuracy: {rf_acc:.2%}
  - XGBoost Accuracy: {xgb_acc:.2%}

Key Finding:
  Model trained on PyPI packages {"CAN" if max(rf_acc, xgb_acc) > 0.7 else "CANNOT"} detect npm malware!
  This demonstrates {"successful" if max(rf_acc, xgb_acc) > 0.7 else "limited"} cross-platform pattern transfer.
""")
    
    return results, rf, xgb_model

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    results, rf_model, xgb_model = train_and_evaluate()
