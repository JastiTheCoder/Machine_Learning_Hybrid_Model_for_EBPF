"""
Proper K-Fold Cross-Validation for Native Captures
===================================================

This script runs stratified k-fold cross-validation on the captured npm
package data to get HONEST, ROBUST performance estimates.

Why this matters:
- A single train/test split with 5 malware samples is unreliable
- One sample difference = 20% swing in recall
- Cross-validation tests every sample exactly once, giving stable estimates

Usage:
    python cross_validation_proper.py --benign ../captures/benign --malware ../captures/malware
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

RANDOM_STATE = 42
OUTPUT_DIR = Path(__file__).parent / "outputs"

# Columns that must never be features (would cause data leakage)
LEAKY_COLUMNS = {
    "label", "severity_score", "verdict_score", "verdict_level",
    "package_name", "session_id", "capture_source", "origin",
    "schema_version", "timed_out", "source_file",
}


def flatten(session: dict) -> dict:
    """Flatten one session JSON into a single-level feature dict."""
    flat = {
        "session_id": session.get("session_id"),
        "package_name": session.get("package_name", ""),
    }

    for prefix, block in (
        ("ft", session.get("filetop", {})),
        ("inst", session.get("install", {})),
        ("os", session.get("opensnoop", {})),
        ("tcp", session.get("tcp", {})),
        ("sc", session.get("syscalls", {})),
        ("pat", session.get("patterns", {})),
        ("sens", session.get("sensitive", {})),
    ):
        for key, value in (block or {}).items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                flat[f"{prefix}_{key}"] = value

    flat["label"] = session.get("label")
    return flat


def load_directory(path: Path, label: int) -> list[dict]:
    """Load every session JSON under path with given label."""
    if not path.exists():
        print(f"  {path}: does not exist")
        return []

    rows = []
    for f in sorted(path.rglob("*.json")):
        try:
            session = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"  SKIP {f.name}: {exc}")
            continue

        row = flatten(session)
        row["label"] = label  # Override with provided label
        row["source_file"] = f.name
        rows.append(row)

    print(f"  {path}: {len(rows)} session(s) loaded")
    return rows


def select_features(df: pd.DataFrame) -> list[str]:
    """Return usable numeric feature columns."""
    candidates = [
        c for c in df.columns
        if c not in LEAKY_COLUMNS
        and pd.api.types.is_numeric_dtype(df[c])
    ]
    
    # Drop constant columns (can't help classification)
    constant = [c for c in candidates if df[c].nunique(dropna=False) <= 1]
    candidates = [c for c in candidates if c not in constant]
    
    if constant:
        print(f"  Dropped {len(constant)} constant columns")
    
    return candidates


def run_cross_validation(X, y, n_splits=5):
    """
    Run stratified k-fold cross-validation and return detailed results.
    
    Stratified means each fold has the same ratio of benign:malicious.
    """
    print(f"\n{'='*70}")
    print(f" STRATIFIED {n_splits}-FOLD CROSS-VALIDATION")
    print(f"{'='*70}")
    print(f"\nWhat this means:")
    print(f"  - Data is split into {n_splits} equal parts")
    print(f"  - Each part maintains the {int(sum(y==0))}:{int(sum(y==1))} benign:malware ratio")
    print(f"  - Each sample is tested exactly once")
    print(f"  - We report AVERAGE performance across all folds")
    
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
    
    # Build models
    n_pos = int(sum(y))
    n_neg = int(len(y) - n_pos)
    ratio = n_neg / n_pos if n_pos > 0 else 1.0
    
    models = {
        "LogisticRegression": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=2000, class_weight="balanced", random_state=RANDOM_STATE)
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced",
            max_depth=6, min_samples_leaf=3,  # Regularization to prevent overfitting
            random_state=RANDOM_STATE, n_jobs=-1
        ),
    }
    
    if HAS_XGB:
        models["XGBoost"] = XGBClassifier(
            n_estimators=300, max_depth=4, learning_rate=0.1,
            scale_pos_weight=ratio,
            reg_alpha=0.1, reg_lambda=1.0,  # Regularization
            eval_metric="logloss", random_state=RANDOM_STATE
        )
    
    all_results = []
    
    for name, model in models.items():
        print(f"\n--- {name} ---")
        
        # Get cross-validated predictions
        y_pred = cross_val_predict(model, X, y, cv=cv)
        
        try:
            y_proba = cross_val_predict(model, X, y, cv=cv, method="predict_proba")[:, 1]
        except:
            y_proba = None
        
        # Calculate metrics
        acc = accuracy_score(y, y_pred)
        prec = precision_score(y, y_pred, zero_division=0)
        rec = recall_score(y, y_pred, zero_division=0)
        f1 = f1_score(y, y_pred, zero_division=0)
        
        if y_proba is not None:
            auc = roc_auc_score(y, y_proba)
        else:
            auc = None
        
        # Confusion matrix
        cm = confusion_matrix(y, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
        
        print(f"  Accuracy:  {acc:.1%}")
        print(f"  Precision: {prec:.1%}  (of packages flagged as malware, how many really are)")
        print(f"  Recall:    {rec:.1%}  (of actual malware, how many did we catch)")
        print(f"  F1 Score:  {f1:.1%}  (balance of precision and recall)")
        if auc:
            print(f"  ROC AUC:   {auc:.3f}")
        
        print(f"\n  Confusion Matrix:")
        print(f"                      Predicted")
        print(f"                   Benign  Malware")
        print(f"    Actual Benign   [{tn:3d}]    [{fp:3d}]")
        print(f"    Actual Malware  [{fn:3d}]    [{tp:3d}]")
        
        print(f"\n  In plain English:")
        print(f"    - Correctly identified {tn} benign packages")
        print(f"    - Correctly caught {tp} malware packages")
        print(f"    - Missed {fn} malware (FALSE NEGATIVES - dangerous!)")
        print(f"    - Wrongly flagged {fp} benign as malware (false positives)")
        
        all_results.append({
            "model": name,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": auc,
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "true_negatives": tn,
        })
    
    return pd.DataFrame(all_results)


def run_per_fold_analysis(X, y, n_splits=5):
    """
    Show performance on EACH fold to see variance.
    """
    print(f"\n{'='*70}")
    print(f" PER-FOLD BREAKDOWN (seeing the variance)")
    print(f"{'='*70}")
    
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
    
    n_pos = int(sum(y))
    n_neg = int(len(y) - n_pos)
    ratio = n_neg / n_pos if n_pos > 0 else 1.0
    
    if HAS_XGB:
        model = XGBClassifier(
            n_estimators=300, max_depth=4, learning_rate=0.1,
            scale_pos_weight=ratio,
            reg_alpha=0.1, reg_lambda=1.0,
            eval_metric="logloss", random_state=RANDOM_STATE
        )
        model_name = "XGBoost"
    else:
        model = RandomForestClassifier(
            n_estimators=300, class_weight="balanced",
            max_depth=6, min_samples_leaf=3,
            random_state=RANDOM_STATE, n_jobs=-1
        )
        model_name = "RandomForest"
    
    print(f"\nUsing {model_name} to show per-fold results:\n")
    
    fold_results = []
    
    for fold_idx, (train_idx, test_idx) in enumerate(cv.split(X, y), 1):
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
        
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        
        acc = accuracy_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred, zero_division=0)
        
        n_mal_test = int(sum(y_test))
        n_mal_caught = int(sum((y_test == 1) & (y_pred == 1)))
        
        print(f"  Fold {fold_idx}: {len(test_idx):2d} samples ({n_mal_test} malware) → "
              f"Accuracy {acc:.0%}, Recall {rec:.0%} ({n_mal_caught}/{n_mal_test} malware caught)")
        
        fold_results.append({"fold": fold_idx, "accuracy": acc, "recall": rec})
    
    fold_df = pd.DataFrame(fold_results)
    
    print(f"\n  Summary across folds:")
    print(f"    Accuracy: {fold_df['accuracy'].mean():.1%} ± {fold_df['accuracy'].std():.1%}")
    print(f"    Recall:   {fold_df['recall'].mean():.1%} ± {fold_df['recall'].std():.1%}")
    
    return fold_df


def analyze_feature_importance(X, y, features):
    """Show which features matter most."""
    print(f"\n{'='*70}")
    print(f" FEATURE IMPORTANCE (what the model looks at)")
    print(f"{'='*70}")
    
    n_pos = int(sum(y))
    n_neg = int(len(y) - n_pos)
    
    rf = RandomForestClassifier(
        n_estimators=300, class_weight="balanced",
        max_depth=6, min_samples_leaf=3,
        random_state=RANDOM_STATE, n_jobs=-1
    )
    rf.fit(X, y)
    
    importance = pd.DataFrame({
        "feature": features,
        "importance": rf.feature_importances_
    }).sort_values("importance", ascending=False)
    
    print("\nTop 15 Most Important Features:\n")
    for i, (_, row) in enumerate(importance.head(15).iterrows(), 1):
        bar = "█" * int(row["importance"] * 100)
        print(f"  {i:2d}. {row['feature']:<30} {row['importance']:.3f} {bar}")
    
    # Save to file
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    importance.to_csv(OUTPUT_DIR / "cv_feature_importance.csv", index=False)
    
    return importance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign", type=Path, required=True)
    parser.add_argument("--malware", type=Path, required=True)
    parser.add_argument("--folds", type=int, default=5, help="Number of CV folds")
    args = parser.parse_args()
    
    print("="*70)
    print(" PROPER CROSS-VALIDATION ON NATIVE CAPTURES")
    print("="*70)
    
    # Load data
    print("\nLoading data:")
    rows = []
    rows += load_directory(args.benign, label=0)
    rows += load_directory(args.malware, label=1)
    
    if not rows:
        print("No data found!")
        return 1
    
    df = pd.DataFrame(rows)
    
    n_benign = int(sum(df["label"] == 0))
    n_malware = int(sum(df["label"] == 1))
    
    print(f"\nDataset: {len(df)} samples")
    print(f"  Benign:  {n_benign} ({n_benign/len(df):.0%})")
    print(f"  Malware: {n_malware} ({n_malware/len(df):.0%})")
    
    # Check if we have enough for CV
    if n_malware < args.folds:
        print(f"\n⚠️  WARNING: Only {n_malware} malware samples!")
        print(f"   Need at least {args.folds} for {args.folds}-fold CV.")
        print(f"   Some folds may have 0 malware in test set.")
        args.folds = min(args.folds, n_malware)
        print(f"   Reducing to {args.folds}-fold CV.\n")
    
    # Select features
    print("\nFeature selection:")
    features = select_features(df)
    print(f"  Using {len(features)} features")
    
    X = df[features].fillna(0)
    y = df["label"].astype(int)
    
    # Run cross-validation
    results = run_cross_validation(X, y, n_splits=args.folds)
    
    # Show per-fold breakdown
    fold_results = run_per_fold_analysis(X, y, n_splits=args.folds)
    
    # Feature importance
    importance = analyze_feature_importance(X, y, features)
    
    # Save results
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results.to_csv(OUTPUT_DIR / "cv_results.csv", index=False)
    fold_results.to_csv(OUTPUT_DIR / "cv_per_fold.csv", index=False)
    
    # Final summary
    print(f"\n{'='*70}")
    print(" FINAL SUMMARY")
    print("="*70)
    
    print("\nCross-Validation Results (averaged across all folds):")
    print(results.to_string(index=False))
    
    best = results.loc[results["recall"].idxmax()]
    print(f"\nBest model by Recall: {best['model']}")
    print(f"  Recall: {best['recall']:.1%} (caught {int(best['true_positives'])} out of {n_malware} malware)")
    print(f"  Precision: {best['precision']:.1%}")
    print(f"  False Positives: {int(best['false_positives'])} benign packages wrongly flagged")
    
    print(f"\n📊 Results saved to:")
    print(f"   {OUTPUT_DIR / 'cv_results.csv'}")
    print(f"   {OUTPUT_DIR / 'cv_per_fold.csv'}")
    print(f"   {OUTPUT_DIR / 'cv_feature_importance.csv'}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
