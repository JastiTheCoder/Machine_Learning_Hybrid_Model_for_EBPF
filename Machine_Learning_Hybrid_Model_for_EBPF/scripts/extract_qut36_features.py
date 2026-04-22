"""
Extract and save 36 QUT-DV25 features from parsed data only.

This avoids retraining other models and writes:
processed/qut36_features/{X,y}_{train,val,test}.npy + feature_names.json
"""

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.qut_feature_extractor import (
    QUT_FEATURE_NAMES,
    extract_qut_features_from_parsed_data,
)


def load_parsed_data(data_dir: Path):
    benign_path = data_dir / "processed" / "benign_parsed.json"
    malicious_path = data_dir / "processed" / "malicious_parsed.json"

    with open(benign_path, "r", encoding="utf-8") as f:
        benign_data = json.load(f)
    with open(malicious_path, "r", encoding="utf-8") as f:
        malicious_data = json.load(f)

    return benign_data, malicious_data


def main() -> None:
    data_dir = PROJECT_ROOT / "data"
    out_dir = PROJECT_ROOT / "processed" / "qut36_features"
    out_dir.mkdir(parents=True, exist_ok=True)

    benign_data, malicious_data = load_parsed_data(data_dir)

    X, y, feature_names, _ = extract_qut_features_from_parsed_data(
        benign_data, malicious_data
    )

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

    with open(out_dir / "feature_names.json", "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)

    print("Saved 36-feature arrays to:", out_dir)
    print("Feature count:", len(feature_names))
    print("Train/Val/Test:", X_train.shape, X_val.shape, X_test.shape)


if __name__ == "__main__":
    main()
