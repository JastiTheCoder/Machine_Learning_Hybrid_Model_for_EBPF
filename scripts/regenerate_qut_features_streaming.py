"""
Rebuild processed/qut_features from QUT parsed JSON without loading 18GB+ into RAM.

The benign/malicious files are huge on disk because each sample has long trace lists,
but there are only ~100 samples per class. This script streams one sample at a time
using ijson, extracts the 36 QUT features, then saves the same .npy layout as
extract_qut_features_only.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import ijson
import numpy as np
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.qut_feature_extractor import QUT_FEATURE_NAMES, QUTFeatureExtractor


def stream_extract(path: Path, label: int, extractor: QUTFeatureExtractor):
    with path.open("rb") as f:
        for sample in ijson.items(f, "item"):
            if not isinstance(sample, dict):
                continue
            row = dict(sample)
            row["label"] = label
            yield extractor.extract_features(row)


def main() -> None:
    data_dir = PROJECT_ROOT / "data"
    benign_path = data_dir / "processed" / "benign_parsed.json"
    malicious_path = data_dir / "processed" / "malicious_parsed.json"
    out_dir = PROJECT_ROOT / "processed" / "qut_features"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not benign_path.is_file() or not malicious_path.is_file():
        raise SystemExit(f"Missing {benign_path} or {malicious_path}")

    extractor = QUTFeatureExtractor()
    all_features = []
    print("Streaming benign samples...")
    for fs in stream_extract(benign_path, 0, extractor):
        all_features.append(fs)
    print(f"  benign count: {len(all_features)}")

    n_benign = len(all_features)
    print("Streaming malicious samples...")
    for fs in stream_extract(malicious_path, 1, extractor):
        all_features.append(fs)
    print(f"  malicious count: {len(all_features) - n_benign} (total {len(all_features)})")

    X = np.array([f.to_feature_vector() for f in all_features], dtype=np.float32)
    y = np.array([f.label for f in all_features], dtype=np.int64)

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )

    np.save(out_dir / "X_train.npy", X_train)
    np.save(out_dir / "X_val.npy", X_val)
    np.save(out_dir / "X_test.npy", X_test)
    np.save(out_dir / "y_train.npy", y_train)
    np.save(out_dir / "y_val.npy", y_val)
    np.save(out_dir / "y_test.npy", y_test)

    with open(out_dir / "feature_names.json", "w", encoding="utf-8") as fh:
        json.dump(QUT_FEATURE_NAMES, fh, indent=2)

    print("Saved:", out_dir)
    print("Shapes train/val/test:", X_train.shape, X_val.shape, X_test.shape)
    print(
        "Class balance train - benign:",
        int((y_train == 0).sum()),
        "malicious:",
        int((y_train == 1).sum()),
    )


if __name__ == "__main__":
    main()
