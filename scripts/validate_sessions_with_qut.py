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
from typing import Dict, List, Optional, Tuple

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
from scripts.import_sessions_to_qut import derive_label, extract_feature_vector


def default_ebpf_session_dirs(project_root: Path) -> List[Path]:
    """
    Primary npm-ebpf-monitor exports under the repo, then optional Desktop sibling
    `capstone_ebpf_repo` (labeled JSON drops). Order matters: earlier dirs win
    when the same filename appears in more than one place (see load_session_features).
    """
    dirs: List[Path] = []
    d1 = project_root / "capstone-main(aniruddha_imp)" / "capstone-main" / "sessions"
    if d1.is_dir():
        dirs.append(d1)
    d2 = project_root / "capstone-main(aniruddha_imp)" / "capstone-main" / "sessions_holdout"
    if d2.is_dir():
        dirs.append(d2)
    extra = project_root.parent / "capstone_ebpf_repo"
    if extra.is_dir():
        dirs.append(extra)
    return dirs


def load_qut_arrays(qut_dir: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Load QUT train/val arrays from disk."""
    x_train = np.load(qut_dir / "X_train.npy")
    y_train = np.load(qut_dir / "y_train.npy")
    x_val = np.load(qut_dir / "X_val.npy")
    y_val = np.load(qut_dir / "y_val.npy")
    return x_train, y_train, x_val, y_val


def load_session_features(session_dirs: List[Path]) -> Tuple[np.ndarray, np.ndarray, List[Dict]]:
    """Load eBPF session JSONs and return features, labels, and metadata.

    If the same basename appears in multiple directories, the first directory
    in the list that yields a row with an integer ``label`` wins. Skipped files
    (missing label) do not consume the basename, so a later directory can still
    supply that session (e.g. unlabeled export in-repo vs labeled drop on Desktop).
    """
    rows: List[List[float]] = []
    labels: List[int] = []
    meta: List[Dict] = []
    skipped = 0
    seen_loaded: set = set()

    for session_dir in session_dirs:
        if not session_dir.exists():
            print(f"WARN: sessions dir not found: {session_dir}")
            continue
        for path in sorted(session_dir.glob("*.json")):
            if path.name in seen_loaded:
                continue
            with open(path, "r", encoding="utf-8") as f:
                record = json.load(f)

            label = record.get("label", None)
            if not isinstance(label, int):
                label = derive_label(record, path.name)
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
            seen_loaded.add(path.name)

    if not rows:
        raise RuntimeError("No labeled session JSON files found.")

    if skipped > 0:
        print(f"WARN: skipped {skipped} sessions without integer label field")

    x = np.asarray(rows, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int64)
    return x, y, meta


def tune_threshold_f1(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    step: float = 0.025,
) -> Tuple[float, float]:
    """
    Pick a decision threshold (malicious if proba >= t) that maximizes F1 for
    the positive class (malicious = 1). Tie-break: higher recall, then higher
    precision. Requires both classes in y_true.
    """
    best_t = 0.5
    best_f1 = -1.0
    best_recall = -1.0
    best_precision = -1.0
    t = float(step)
    while t < 1.0:
        pred = (y_proba >= t).astype(np.int64)
        f1v = f1_score(y_true, pred, pos_label=1, zero_division=0)
        rec = recall_score(y_true, pred, pos_label=1, zero_division=0)
        pre = precision_score(y_true, pred, pos_label=1, zero_division=0)
        if (
            f1v > best_f1
            or (
                f1v == best_f1
                and (rec > best_recall or (rec == best_recall and pre > best_precision))
            )
        ):
            best_f1 = f1v
            best_t = t
            best_recall = rec
            best_precision = pre
        t += step
    return best_t, best_f1


def write_predictions_csv(out_path: Path, meta: List[Dict], extra_fields: Optional[List[str]] = None) -> None:
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
    if extra_fields:
        for name in extra_fields:
            if name not in fieldnames:
                fieldnames.append(name)
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
    parser.add_argument(
        "--tune-threshold",
        action="store_true",
        help=(
            "Search thresholds on the same eBPF set used for metrics (exploratory; "
            "optimistic when n is small). Adds tuned columns to the CSV when set."
        ),
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
        session_dirs = default_ebpf_session_dirs(PROJECT_ROOT)

    if not session_dirs:
        raise RuntimeError(
            "No session directories configured. Add "
            "capstone-main(aniruddha_imp)/capstone-main/sessions or pass --sessions-dir."
        )

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

    extra_csv_fields: Optional[List[str]] = None
    if args.tune_threshold:
        if len(np.unique(y_val_ebpf)) < 2:
            print(
                "\nNOTE: --tune-threshold skipped (need both benign and malicious labels)."
            )
        else:
            auc_raw = float(roc_auc_score(y_val_ebpf, y_proba))
            score = y_proba.astype(np.float64, copy=True)
            inverted = False
            if auc_raw < 0.5:
                score = 1.0 - y_proba
                inverted = True
                print(
                    f"\nNOTE: For threshold search only, using (1 - model_output) "
                    f"because raw ROC AUC was {auc_raw:.4f} (< 0.5) on this slice."
                )
            best_t, best_f1 = tune_threshold_f1(y_val_ebpf, score)
            y_pred_t = (score >= best_t).astype(np.int64)
            print("\n--- Exploratory threshold search (same eBPF set as above) ---")
            print(
                "NOTE: Threshold is chosen on the same rows used for scoring; "
                "with very few sessions this is optimistic. Collect more labeled "
                "sessions for unbiased tuning."
            )
            if inverted:
                print(
                    "Tuned rule: malicious if (1 - raw_probability) >= t "
                    f"(equivalently raw_probability <= {1.0 - best_t:.4f})."
                )
            else:
                print("Tuned rule: malicious if raw_probability >= t")
            print(f"Chosen threshold t: {best_t:.4f} (F1 on this set: {best_f1:.4f})")
            print(f"Accuracy at t:  {accuracy_score(y_val_ebpf, y_pred_t):.4f}")
            print(
                f"Precision at t: {precision_score(y_val_ebpf, y_pred_t, pos_label=1, zero_division=0):.4f}"
            )
            print(
                f"Recall at t:    {recall_score(y_val_ebpf, y_pred_t, pos_label=1, zero_division=0):.4f}"
            )
            print(
                f"F1 at t:        {f1_score(y_val_ebpf, y_pred_t, pos_label=1, zero_division=0):.4f}"
            )
            cm_t = confusion_matrix(y_val_ebpf, y_pred_t, labels=[0, 1])
            print("\nConfusion matrix at tuned threshold:")
            print("                    Predicted")
            print("                    Benign  Malicious")
            print(f"Actual Benign            {int(cm_t[0,0]):4d}      {int(cm_t[0,1]):4d}")
            print(f"Actual Malicious         {int(cm_t[1,0]):4d}      {int(cm_t[1,1]):4d}")
            for i, row in enumerate(meta):
                row["predicted_label_tuned"] = int(y_pred_t[i])
                row["threshold_used"] = float(best_t)
                row["correct_tuned"] = int(row["true_label"] == y_pred_t[i])
                row["tuning_score_inverted"] = int(inverted)
            extra_csv_fields = [
                "predicted_label_tuned",
                "threshold_used",
                "correct_tuned",
                "tuning_score_inverted",
            ]

    out_csv = Path(args.out_csv)
    if not out_csv.is_absolute():
        out_csv = PROJECT_ROOT / out_csv
    write_predictions_csv(out_csv, meta, extra_fields=extra_csv_fields)
    print("Per-file predictions saved to:", out_csv)


if __name__ == "__main__":
    main()
