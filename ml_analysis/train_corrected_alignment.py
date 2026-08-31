"""
Train with Corrected Feature Alignment
======================================
Now that we've confirmed both npm and PyPI are IN-DISTRIBUTION when using
proper count-vs-count comparison, let's retrain and evaluate.

Training data: QUT Reference (196 packages with actual frequency counts)
Test data: Our captures (3 PyPI + 14 npm)
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
warnings.filterwarnings('ignore')

# ============================================================================
# CONFIGURATION
# ============================================================================

SCRIPT_DIR = Path(__file__).parent
QUT_REF = SCRIPT_DIR / "qut-reference-196.csv"
CORPUS_17 = SCRIPT_DIR / "corpus-17-schema2.csv"
OUTPUT_DIR = SCRIPT_DIR / "outputs"

# Pattern count features (the aligned features)
FEATURES = ['p1_count', 'p2_count', 'p3_count', 'p4_count', 'p5_count']

# ============================================================================
# LOAD DATA
# ============================================================================

def load_qut_reference():
    """Load QUT reference with actual frequency counts."""
    print("=" * 70)
    print("LOADING QUT REFERENCE (Training Data)")
    print("=" * 70)
    
    df = pd.read_csv(QUT_REF, encoding='utf-8-sig')
    
    print(f"  Samples: {len(df)}")
    print(f"  Benign: {sum(df['label'] == 0)}")
    print(f"  Malicious: {sum(df['label'] == 1)}")
    
    return df

def load_test_data():
    """Load our captures as test data."""
    print("\n" + "=" * 70)
    print("LOADING TEST DATA (Our Captures)")
    print("=" * 70)
    
    corpus = pd.read_csv(CORPUS_17, encoding='utf-8-sig')
    
    pypi_mask = corpus['package_name'].str.contains('pypi', case=False, na=False)
    pypi_rows = corpus[pypi_mask].copy()
    npm_rows = corpus[~pypi_mask].copy()
    
    print(f"\n  PyPI: {len(pypi_rows)} rows")
    for _, row in pypi_rows.iterrows():
        label = "MAL" if row['label'] == 1 else "BEN"
        print(f"    [{label}] {row['package_name']}")
    
    print(f"\n  npm: {len(npm_rows)} rows")
    npm_benign = npm_rows[npm_rows['label'] == 0]
    npm_malicious = npm_rows[npm_rows['label'] == 1]
    print(f"    Benign: {len(npm_benign)}")
    print(f"    Malicious: {len(npm_malicious)}")
    
    return pypi_rows, npm_rows, corpus

# ============================================================================
# TRAINING AND EVALUATION
# ============================================================================

def train_and_evaluate():
    """Train on QUT, test on our captures."""
    
    qut_df = load_qut_reference()
    pypi_rows, npm_rows, all_test = load_test_data()
    
    # Prepare training data
    X_train = qut_df[FEATURES].values
    y_train = qut_df['label'].values
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # =========================================================================
    # STEP 1: Cross-validation on QUT data
    # =========================================================================
    print("\n" + "=" * 70)
    print("STEP 1: Cross-Validation on QUT Reference (5 Pattern Features)")
    print("=" * 70)
    
    rf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_acc = cross_val_score(rf, X_train_scaled, y_train, cv=cv, scoring='accuracy')
    cv_f1 = cross_val_score(rf, X_train_scaled, y_train, cv=cv, scoring='f1')
    
    print(f"\n  5-Fold CV Accuracy: {cv_acc.mean():.4f} (+/- {cv_acc.std()*2:.4f})")
    print(f"  5-Fold CV F1 Score: {cv_f1.mean():.4f} (+/- {cv_f1.std()*2:.4f})")
    
    # =========================================================================
    # STEP 2: Train final model
    # =========================================================================
    print("\n" + "=" * 70)
    print("STEP 2: Train Final Model on QUT Reference")
    print("=" * 70)
    
    rf_final = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    rf_final.fit(X_train_scaled, y_train)
    
    print(f"\n  Training accuracy: {rf_final.score(X_train_scaled, y_train):.4f}")
    
    # Feature importances
    print("\n  Feature Importances:")
    importances = pd.Series(rf_final.feature_importances_, index=FEATURES)
    for feat, imp in importances.sort_values(ascending=False).items():
        print(f"    {feat}: {imp:.4f}")
    
    # =========================================================================
    # STEP 3: Test on PyPI captures
    # =========================================================================
    print("\n" + "=" * 70)
    print("STEP 3: Test on PyPI Captures")
    print("=" * 70)
    
    X_pypi = pypi_rows[FEATURES].values
    y_pypi = pypi_rows['label'].values
    X_pypi_scaled = scaler.transform(X_pypi)
    
    pypi_pred = rf_final.predict(X_pypi_scaled)
    pypi_prob = rf_final.predict_proba(X_pypi_scaled)[:, 1]
    
    print(f"\n{'Package':<35} {'Actual':>10} {'Pred':>10} {'Prob':>10} {'Correct':>10}")
    print("-" * 80)
    
    pypi_correct = 0
    for idx, row in pypi_rows.iterrows():
        actual = "MAL" if row['label'] == 1 else "BEN"
        pred = "MAL" if pypi_pred[pypi_rows.index.get_loc(idx)] == 1 else "BEN"
        prob = pypi_prob[pypi_rows.index.get_loc(idx)]
        correct = "YES" if actual == pred else "NO"
        if actual == pred:
            pypi_correct += 1
        print(f"{row['package_name']:<35} {actual:>10} {pred:>10} {prob:>9.1%} {correct:>10}")
    
    pypi_acc = pypi_correct / len(pypi_rows)
    print(f"\n  PyPI Accuracy: {pypi_acc:.1%} ({pypi_correct}/{len(pypi_rows)})")
    
    # =========================================================================
    # STEP 4: Test on npm captures
    # =========================================================================
    print("\n" + "=" * 70)
    print("STEP 4: Test on npm Captures")
    print("=" * 70)
    
    X_npm = npm_rows[FEATURES].values
    y_npm = npm_rows['label'].values
    X_npm_scaled = scaler.transform(X_npm)
    
    npm_pred = rf_final.predict(X_npm_scaled)
    npm_prob = rf_final.predict_proba(X_npm_scaled)[:, 1]
    
    print(f"\n{'Package':<35} {'Actual':>10} {'Pred':>10} {'Prob':>10} {'Correct':>10}")
    print("-" * 80)
    
    npm_correct = 0
    npm_mal_correct = 0
    npm_mal_total = 0
    for idx, row in npm_rows.iterrows():
        actual = "MAL" if row['label'] == 1 else "BEN"
        pred = "MAL" if npm_pred[npm_rows.index.get_loc(idx)] == 1 else "BEN"
        prob = npm_prob[npm_rows.index.get_loc(idx)]
        correct = "YES" if actual == pred else "NO"
        if actual == pred:
            npm_correct += 1
        if row['label'] == 1:
            npm_mal_total += 1
            if pred == "MAL":
                npm_mal_correct += 1
        print(f"{row['package_name']:<35} {actual:>10} {pred:>10} {prob:>9.1%} {correct:>10}")
    
    npm_acc = npm_correct / len(npm_rows)
    npm_recall = npm_mal_correct / npm_mal_total if npm_mal_total > 0 else 0
    
    print(f"\n  npm Accuracy: {npm_acc:.1%} ({npm_correct}/{len(npm_rows)})")
    print(f"  npm Malicious Recall: {npm_recall:.1%} ({npm_mal_correct}/{npm_mal_total})")
    
    # =========================================================================
    # STEP 5: Combined test results
    # =========================================================================
    print("\n" + "=" * 70)
    print("STEP 5: Combined Results")
    print("=" * 70)
    
    X_all = all_test[FEATURES].values
    y_all = all_test['label'].values
    X_all_scaled = scaler.transform(X_all)
    
    all_pred = rf_final.predict(X_all_scaled)
    
    print("\nClassification Report (All Test Data):")
    print(classification_report(y_all, all_pred, target_names=['Benign', 'Malicious']))
    
    print("Confusion Matrix:")
    cm = confusion_matrix(y_all, all_pred)
    print(f"                 Predicted")
    print(f"                 Benign  Malicious")
    print(f"Actual Benign    {cm[0,0]:5d}      {cm[0,1]:5d}")
    print(f"Actual Malicious {cm[1,0]:5d}      {cm[1,1]:5d}")
    
    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    
    total_correct = (all_pred == y_all).sum()
    total_acc = total_correct / len(y_all)
    
    mal_mask = y_all == 1
    mal_recall = (all_pred[mal_mask] == 1).sum() / mal_mask.sum() if mal_mask.sum() > 0 else 0
    
    ben_mask = y_all == 0
    ben_recall = (all_pred[ben_mask] == 0).sum() / ben_mask.sum() if ben_mask.sum() > 0 else 0
    
    print(f"""
    Training: QUT Reference (196 samples, 5 pattern count features)
    Test: Our captures (17 samples: 3 PyPI + 14 npm)
    
    QUT CV Accuracy: {cv_acc.mean():.1%}
    QUT CV F1 Score: {cv_f1.mean():.1%}
    
    Test Results:
    - Overall Accuracy: {total_acc:.1%}
    - Benign Recall (Specificity): {ben_recall:.1%}
    - Malicious Recall (Sensitivity): {mal_recall:.1%}
    
    Comparison with Original (0% recall):
    - Original malicious recall: 0%
    - New malicious recall: {mal_recall:.1%}
    - Improvement: {"YES - Model now detects malicious packages!" if mal_recall > 0 else "No improvement"}
    """)
    
    # Save results
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    results = all_test[['package_name', 'label']].copy()
    results['prediction'] = all_pred
    results['probability'] = rf_final.predict_proba(X_all_scaled)[:, 1]
    results['correct'] = results['label'] == results['prediction']
    results.to_csv(OUTPUT_DIR / "corrected_alignment_predictions.csv", index=False)
    
    print(f"  Predictions saved to: {OUTPUT_DIR / 'corrected_alignment_predictions.csv'}")
    
    return {
        'cv_accuracy': cv_acc.mean(),
        'test_accuracy': total_acc,
        'malicious_recall': mal_recall,
        'benign_recall': ben_recall
    }

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("\n" + "#" * 70)
    print("#  TRAIN WITH CORRECTED FEATURE ALIGNMENT")
    print("#  Using QUT Reference (actual frequency counts)")
    print("#" * 70)
    
    results = train_and_evaluate()
