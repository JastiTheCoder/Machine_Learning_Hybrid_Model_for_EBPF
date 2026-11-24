"""
Train the saved Random Forest API model from native capture JSON.

This script intentionally:
- uses the same flattening rules as train_native.py
- excludes package names, session IDs and verdict-derived columns
- removes constant features
- performs a family/package-grouped demo split
- saves the exact feature order in model_metadata.json
"""

import argparse
import json
import pickle
import sys
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler


LEAKY_COLUMNS = {
    "label",
    "severity_score",
    "verdict_score",
    "verdict_level",
    "package_name",
    "session_id",
    "capture_source",
    "origin",
    "schema_version",
    "timed_out",
}


def flatten(session):
    row = {
        "session_id": session.get("session_id"),
        "package_name": session.get("package_name", ""),
        "schema_version": session.get("schema_version", "1.0.0"),
        "capture_source": session.get("capture_source", ""),
        "label": session.get("label"),
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
                row[f"{prefix}_{key}"] = value

    verdict = session.get("verdict") or {}
    row["verdict_score"] = verdict.get("score", 0)
    row["verdict_level"] = verdict.get("level", "none")
    return row


def load_directory(path, label):
    rows = []
    excluded = []
    for file_path in sorted(path.rglob("*.json")):
        try:
            capture = json.loads(file_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        row = flatten(capture)
        recorded_label = capture.get("label")
        if recorded_label is not None:
            row["label"] = int(recorded_label)
        else:
            row["label"] = label

        package_name = str(capture.get("package_name") or file_path.stem)
        row["package_name"] = package_name
        row["family_group"] = package_name
        row["source_file"] = file_path.name
        rows.append(row)

    return rows


def select_features(frame):
    candidates = [
        column
        for column in frame.columns
        if column not in LEAKY_COLUMNS
        and column not in {"source_file", "family_group"}
        and pd.api.types.is_numeric_dtype(frame[column])
    ]

    schemas = set(frame["schema_version"].dropna())
    pre_12 = {schema for schema in schemas if str(schema) < "1.2.0"}
    if pre_12 and len(schemas) > 1:
        candidates = [column for column in candidates if not column.startswith("pat_")]
        candidates = [
            column
            for column in candidates
            if not column.startswith("sens_")
        ]

    constant = [
        column
        for column in candidates
        if frame[column].nunique(dropna=False) <= 1
    ]
    features = [column for column in candidates if column not in constant]
    return features


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--benign", type=Path, required=True)
    parser.add_argument("--malware", type=Path, required=True)
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    rows = load_directory(args.benign, 0)
    rows += load_directory(args.malware, 1)
    if not rows:
        print("ERROR: no native capture JSON files found.")
        return 1

    frame = pd.DataFrame(rows)
    features = select_features(frame)
    if not features:
        print("ERROR: no usable numeric features.")
        return 1

    x = frame[features].fillna(0)
    y = frame["label"].astype(int)
    groups = frame["family_group"].fillna("unknown")

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=args.test_size,
        random_state=args.random_state,
    )
    train_index, test_index = next(splitter.split(x, y, groups=groups))
    x_train = x.iloc[train_index]
    x_test = x.iloc[test_index]
    y_train = y.iloc[train_index]
    y_test = y.iloc[test_index]

    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)

    positive = int(y_train.sum())
    negative = int(len(y_train) - positive)
    model = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        random_state=args.random_state,
        n_jobs=-1,
    )
    model.fit(x_train_scaled, y_train)

    prediction = model.predict(x_test_scaled)
    probability = model.predict_proba(x_test_scaled)[:, 1]

    tn, fp, fn, tp = confusion_matrix(y_test, prediction).ravel()
    accuracy = float((tp + tn) / (tp + tn + fp + fn))
    precision = precision_score(y_test, prediction, zero_division=0)
    recall = recall_score(y_test, prediction, zero_division=0)
    roc_auc = roc_auc_score(y_test, probability)
    pr_auc = average_precision_score(y_test, probability)

    output_dir = Path(__file__).resolve().parent.parent / "ml_analysis"
    with (output_dir / "model.pkl").open("wb") as handle:
        pickle.dump(model, handle)
    with (output_dir / "scaler.pkl").open("wb") as handle:
        pickle.dump(scaler, handle)

    metadata = {
        "model_type": "RandomForestClassifier",
        "features_count": len(features),
        "feature_names": features,
        "training_samples": len(x_train),
        "test_samples": len(x_test),
        "accuracy": accuracy,
        "recall": recall,
        "precision": precision,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "version": "1.0.0-native-captures-api",
    }
    (output_dir / "model_metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    print("Native API model trained")
    print("Feature count:", len(features))
    print("Training samples:", len(x_train))
    print("Test samples:", len(x_test))
    print("TP / FN:", tp, "/", fn)
    print("FP / TN:", fp, "/", tn)
    print("Accuracy:", f"{accuracy:.2%}")
    print("Precision:", f"{precision:.2%}")
    print("Recall:", f"{recall:.2%}")
    print("ROC-AUC:", f"{roc_auc:.4f}")
    print("PR-AUC:", f"{pr_auc:.4f}")
    print("Saved model:", output_dir / "model.pkl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
