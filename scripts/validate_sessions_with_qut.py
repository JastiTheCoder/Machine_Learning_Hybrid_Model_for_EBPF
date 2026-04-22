"""
Train the hybrid model on the QUT dataset and validate on eBPF session JSONs.

This script:
1) Loads pre-extracted QUT arrays from processed/qut_features
2) Trains the hybrid XGBoost+LSTM model on QUT train/val
3) Loads eBPF session JSONs and extracts 36 QUT features
4) Evaluates predictions against JSON `label` fields
"""

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from train_hybrid_model import HybridXGBoostLSTM
from scripts.import_sessions_to_qut import extract_feature_vector


def load_qut_arrays(qut_dir: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Load QUT train/val arrays from disk."""
    x_train = np.load(qut_dir / "X_train.npy")
    y_train = np.load(qut_dir / "y_train.npy")
    x_val = np.load(qut_dir / "X_val.npy")
    y_val = np.load(qut_dir / "y_val.npy")
    return x_train, y_train, x_val, y_val


def load_session_features(session_dirs: List[Path]) -> Tuple[np.ndarray, np.ndarray, List[Dict]]:
    """Load eBPF session JSONs and return features, labels, and metadata."""
    rows: List[List[float]] = []
    labels: List[int] = []
    meta: List[Dict] = []
    skipped = 0

    for session_dir in session_dirs:
        if not session_dir.exists():
            print(f"WARN: sessions dir not found: {session_dir}")
            continue
        for path in sorted(session_dir.glob("*.json")):
            with open(path, "r", encoding="utf-8") as f:
                record = json.load(f)

            label = record.get("label", None)
            if not isinstance(label, int):
                skipped += 1
                continue

            features = extract_feature_vector(record)
            rows.append(features)
            labels.append(label)
            meta.append(
                {
                    "filename": path.name,
                    "package_name": record.get("package_name", path.name),
                    "true_label": label,
                }
            )

    if not rows:
        raise RuntimeError("No labeled session JSON files found.")

    if skipped > 0:
        print(f"WARN: skipped {skipped} sessions without integer label field")

    x = np.asarray(rows, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int64)
    return x, y, meta


def write_predictions_csv(out_path: Path, meta: List[Dict]) -> None:
    """Write per-file prediction results to CSV."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "filename",
        "package_name",
        "true_label",
        "predicted_label",
        "probability",
        "correct",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(meta)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train on QUT and validate on eBPF session JSONs"
    )
    parser.add_argument(
        "--qut-dir",
        type=str,
        default="processed/qut_features",
        help="Path to pre-extracted QUT arrays",
    )
    parser.add_argument(
        "--sessions-dir",
        action="append",
        default=[],
        help="Sessions directory (can be provided multiple times)",
    )
    parser.add_argument(
        "--out-csv",
        type=str,
        default="processed/ebpf_validation_predictions.csv",
        help="Path for per-file prediction CSV",
    )
    args = parser.parse_args()

    qut_dir = Path(args.qut_dir)
    if not qut_dir.is_absolute():
        qut_dir = PROJECT_ROOT / qut_dir

    if not qut_dir.exists():
        raise RuntimeError(f"QUT arrays not found at {qut_dir}")

    session_dirs: List[Path] = []
    if args.sessions_dir:
        for item in args.sessions_dir:
            path = Path(item)
            if not path.is_absolute():
                path = PROJECT_ROOT / path
            session_dirs.append(path)
    else:
        default_dir = PROJECT_ROOT / "capstone-main(aniruddha_imp)" / "capstone-main" / "sessions"
        session_dirs.append(default_dir)
        holdout_dir = PROJECT_ROOT / "capstone-main(aniruddha_imp)" / "capstone-main" / "sessions_holdout"
        if holdout_dir.exists():
            session_dirs.append(holdout_dir)

    print("Loading QUT arrays from:", qut_dir)
    x_train, y_train, x_val, y_val = load_qut_arrays(qut_dir)

    print("Training hybrid model on QUT data...")
    model = HybridXGBoostLSTM(n_features=36)
    model.fit(x_train, y_train, x_val, y_val)

    print("Loading eBPF sessions for validation...")
    x_val_ebpf, y_val_ebpf, meta = load_session_features(session_dirs)

    print("Running predictions on eBPF sessions...")
    y_pred = model.predict(x_val_ebpf)
    y_proba = model.predict_proba(x_val_ebpf)

    for i, row in enumerate(meta):
        row["predicted_label"] = int(y_pred[i])
        row["probability"] = float(y_proba[i])
        row["correct"] = int(row["true_label"] == row["predicted_label"])

    accuracy = accuracy_score(y_val_ebpf, y_pred)
    precision = precision_score(y_val_ebpf, y_pred, zero_division=0)
    recall = recall_score(y_val_ebpf, y_pred, zero_division=0)
    f1 = f1_score(y_val_ebpf, y_pred, zero_division=0)

    if len(np.unique(y_val_ebpf)) < 2:
        auc = float("nan")
        print("WARN: ROC AUC undefined (only one class present in validation set)")
    else:
        auc = roc_auc_score(y_val_ebpf, y_proba)

    print("\nEBPF Validation Metrics")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"ROC AUC:   {auc}")

    cm = confusion_matrix(y_val_ebpf, y_pred, labels=[0, 1])
    print("\nConfusion Matrix (eBPF Validation):")
    print("                    Predicted")
    print("                    Benign  Malicious")
    print(f"Actual Benign            {int(cm[0,0]):4d}      {int(cm[0,1]):4d}")
    print(f"Actual Malicious         {int(cm[1,0]):4d}      {int(cm[1,1]):4d}")

    print(
        "\n"
        + classification_report(
            y_val_ebpf,
            y_pred,
            target_names=["Benign", "Malicious"],
            labels=[0, 1],
            zero_division=0,
        )
    )

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = PROJECT_ROOT / out_csv
    write_predictions_csv(out_csv, meta)
    print("Per-file predictions saved to:", out_csv)


if __name__ == "__main__":
    main()
