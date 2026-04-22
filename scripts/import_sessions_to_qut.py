"""
Import npm-ebpf-monitor session JSON files and emit QUT feature arrays.

This script converts session JSON (aggregated features) into the exact
36-feature QUT layout expected by the hybrid model, then writes
processed/qut_features/{X,y}_{train,val,test}.npy and feature_names.json.
"""

import argparse
import csv
import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
from sklearn.model_selection import StratifiedShuffleSplit, train_test_split

# Ensure project root is on sys.path for src imports.
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.qut_feature_extractor import QUT_FEATURE_NAMES
from src.utils.helpers import ensure_dir, load_config


def _tcp_field(tcp: Dict, snake_key: str, pascal_key: str) -> float:
    """Read TCP counter from session JSON (snake_case or legacy PascalCase)."""
    if snake_key in tcp:
        return float(tcp[snake_key])
    if pascal_key in tcp:
        return float(tcp[pascal_key])
    return 0.0


def derive_label(record: Dict, filename: str) -> int:
    """Determine label from JSON label field or filename/package_name."""
    label = record.get("label", None)
    if isinstance(label, int):
        return label
    package_name = record.get("package_name", "")
    lower_name = f"{filename} {package_name}".lower()
    if "benign-test" in lower_name or "lodash" in lower_name:
        return 0
    if "suspicious" in lower_name or "malicious" in lower_name:
        return 1
    # npm test packages that simulate attacks (label often omitted in exports)
    attack_markers = (
        "stealer",
        "grabber",
        "reverse-shell",
        "shell-test",
        "cryptominer",
        "exfil",
        "ransom",
    )
    if any(m in lower_name for m in attack_markers):
        return 1
    return 0


def extract_feature_vector(record: Dict) -> List[float]:
    """Extract a 36-length feature vector in QUT_FEATURE_NAMES order."""
    filetop = record.get("filetop", {})
    install = record.get("install", {})
    opensnoop = record.get("opensnoop", {})
    tcp = record.get("tcp", {})
    syscalls = record.get("syscalls", {})
    patterns = record.get("patterns", {})

    return [
        # Filetop (5)
        float(filetop.get("read_processes", 0)),
        float(filetop.get("write_processes", 0)),
        float(filetop.get("read_data_transfer_kb", 0)),
        float(filetop.get("write_data_transfer_kb", 0)),
        float(filetop.get("file_access_processes", 0)),
        # Install (3)
        float(install.get("total_dependencies", 0)),
        float(install.get("direct_dependencies", 0)),
        float(install.get("indirect_dependencies", 0)),
        # Opensnoop (7)
        float(opensnoop.get("root_dir_access", 0)),
        float(opensnoop.get("temp_dir_access", 0)),
        float(opensnoop.get("home_dir_access", 0)),
        float(opensnoop.get("user_dir_access", 0)),
        float(opensnoop.get("sys_dir_access", 0)),
        float(opensnoop.get("etc_dir_access", 0)),
        float(opensnoop.get("other_dir_access", 0)),
        # TCP (5) — older session JSON used PascalCase keys (e.g. lodash runs)
        _tcp_field(tcp, "state_transitions", "StateTransitions"),
        _tcp_field(tcp, "local_ips", "LocalIPs"),
        _tcp_field(tcp, "remote_ips", "RemoteIPs"),
        _tcp_field(tcp, "local_ports", "LocalPorts"),
        _tcp_field(tcp, "remote_ports", "RemotePorts"),
        # Syscalls (6)
        float(syscalls.get("io_ops", 0)),
        float(syscalls.get("file_ops", 0)),
        float(syscalls.get("network_ops", 0)),
        float(syscalls.get("time_ops", 0)),
        float(syscalls.get("security_ops", 0)),
        float(syscalls.get("process_ops", 0)),
        # Patterns (10)
        float(patterns.get("p1_file_metadata", 0)),
        float(patterns.get("p2_read_data", 0)),
        float(patterns.get("p3_write_data", 0)),
        float(patterns.get("p4_socket_create", 0)),
        float(patterns.get("p5_process_create", 0)),
        float(patterns.get("p6_memory_map", 0)),
        float(patterns.get("p7_fd_manage", 0)),
        float(patterns.get("p8_ipc", 0)),
        float(patterns.get("p9_file_lock", 0)),
        float(patterns.get("p10_error_handle", 0)),
    ]


def load_sessions(sessions_dir: Path) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """Load session JSON files and return X, y, and package names."""
    X_rows: List[List[float]] = []
    y_rows: List[int] = []
    names: List[str] = []

    for filename in sorted(os.listdir(sessions_dir)):
        if not filename.endswith(".json"):
            continue
        path = sessions_dir / filename
        with open(path, "r", encoding="utf-8") as f:
            record = json.load(f)

        label = derive_label(record, filename)
        features = extract_feature_vector(record)
        X_rows.append(features)
        y_rows.append(label)
        names.append(record.get("package_name", filename))

    if not X_rows:
        raise RuntimeError(f"No JSON sessions found in {sessions_dir}")

    X = np.asarray(X_rows, dtype=np.float32)
    y = np.asarray(y_rows, dtype=np.int64)
    return X, y, names


def load_qut_train_subsample(
    qut_dir: Path, max_rows: int, random_state: int
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load QUT X_train/y_train and return at most max_rows rows, stratified by
    label when possible so both classes stay represented.
    """
    x_path = qut_dir / "X_train.npy"
    y_path = qut_dir / "y_train.npy"
    if not x_path.is_file() or not y_path.is_file():
        raise FileNotFoundError(f"Need {x_path} and {y_path} for --blend-qut-dir")
    xt = np.load(x_path)
    yt = np.load(y_path)
    n = len(yt)
    if n == 0:
        raise RuntimeError("QUT blend arrays are empty.")
    take = min(int(max_rows), n)
    if take == n:
        return xt.astype(np.float32, copy=False), yt.astype(np.int64, copy=False)
    try:
        sss = StratifiedShuffleSplit(
            n_splits=1, train_size=take, random_state=random_state
        )
        tr, _ = next(sss.split(xt, yt))
        return xt[tr].astype(np.float32, copy=False), yt[tr].astype(np.int64, copy=False)
    except ValueError:
        rng = np.random.default_rng(random_state)
        idx = rng.choice(n, size=take, replace=False)
        return xt[idx].astype(np.float32, copy=False), yt[idx].astype(np.int64, copy=False)


def write_qut_csv(sessions_dir: Path, csv_path: Path) -> None:
    """Write a 39-column CSV (package_name + label + 36 features + severity_score)."""
    header = ["package_name", "label"] + QUT_FEATURE_NAMES + ["severity_score"]

    rows: List[List[str]] = []
    for filename in sorted(os.listdir(sessions_dir)):
        if not filename.endswith(".json"):
            continue
        path = sessions_dir / filename
        with open(path, "r", encoding="utf-8") as f:
            record = json.load(f)

        label = derive_label(record, filename)
        features = extract_feature_vector(record)
        package_name = record.get("package_name", filename)
        severity_score = label

        rows.append(
            [str(package_name), str(label)] + [str(v) for v in features] + [str(severity_score)]
        )

    if not rows:
        raise RuntimeError(f"No JSON sessions found in {sessions_dir}")

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Import session JSON to QUT arrays")
    parser.add_argument(
        "--sessions-dir",
        type=str,
        default="capstone-main(aniruddha_imp)/capstone-main/sessions",
        help="Path to npm-ebpf-monitor sessions directory",
    )
    parser.add_argument(
        "--holdout-dir",
        type=str,
        default="",
        help="Optional hold-out sessions directory for test set",
    )
    parser.add_argument(
        "--csv-out",
        type=str,
        default="",
        help="Optional path to write a 39-column CSV for sessions-dir",
    )
    parser.add_argument(
        "--holdout-csv-out",
        type=str,
        default="",
        help="Optional path to write a 39-column CSV for holdout-dir",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="configs/config.yaml",
        help="Path to config file (for split ratios)",
    )
    parser.add_argument(
        "--blend-qut-dir",
        type=str,
        default="",
        help=(
            "Optional folder containing X_train.npy and y_train.npy (QUT). "
            "A subsample is merged with session JSON features before train/val split. "
            "This overwrites processed/qut_features; run "
            "scripts/regenerate_qut_features_streaming.py to restore QUT-only arrays."
        ),
    )
    parser.add_argument(
        "--blend-qut-max",
        type=int,
        default=80,
        help="Max QUT rows to take when --blend-qut-dir is set (default 80).",
    )
    parser.add_argument(
        "--backup-qut-dir",
        type=str,
        default="",
        help=(
            "If set, copies existing processed/qut_features into this folder "
            "under qut_features_backup_YYYYMMDD_HHMMSS before writing new .npy "
            "files (only when X_train.npy already exists)."
        ),
    )
    args = parser.parse_args()

    project_root = PROJECT_ROOT
    sessions_dir = Path(args.sessions_dir)
    if not sessions_dir.is_absolute():
        sessions_dir = project_root / sessions_dir

    holdout_dir = Path(args.holdout_dir) if args.holdout_dir else None
    if holdout_dir is not None and not holdout_dir.is_absolute():
        holdout_dir = project_root / holdout_dir

    config = load_config(args.config)
    split_cfg = config.get("splits", {})
    train_ratio = float(split_cfg.get("train", 0.7))
    val_ratio = float(split_cfg.get("val", 0.15))
    test_ratio = float(split_cfg.get("test", 0.15))

    if abs((train_ratio + val_ratio + test_ratio) - 1.0) > 1e-6:
        raise ValueError("Split ratios must sum to 1.0")

    if args.csv_out:
        csv_path = Path(args.csv_out)
        if not csv_path.is_absolute():
            csv_path = project_root / csv_path
        write_qut_csv(sessions_dir, csv_path)
        print("Saved 39-column CSV to:", csv_path)

    if holdout_dir is not None and args.holdout_csv_out:
        holdout_csv_path = Path(args.holdout_csv_out)
        if not holdout_csv_path.is_absolute():
            holdout_csv_path = project_root / holdout_csv_path
        write_qut_csv(holdout_dir, holdout_csv_path)
        print("Saved holdout 39-column CSV to:", holdout_csv_path)

    X, y, _ = load_sessions(sessions_dir)

    blend_dir_raw = (args.blend_qut_dir or "").strip()
    if blend_dir_raw:
        blend_dir = Path(blend_dir_raw)
        if not blend_dir.is_absolute():
            blend_dir = project_root / blend_dir
        x_q, y_q = load_qut_train_subsample(
            blend_dir, int(args.blend_qut_max), random_state=42
        )
        X = np.vstack([X.astype(np.float32), x_q])
        y = np.concatenate([y.astype(np.int64), y_q])
        print(
            f"Blended {x_q.shape[0]} QUT rows from {blend_dir} "
            f"(max {args.blend_qut_max}). Total rows before split: {X.shape[0]}"
        )

    # Split into train/val/test with stratification (or use holdout for test)
    if holdout_dir is None:
        try:
            X_train, X_temp, y_train, y_temp = train_test_split(
                X, y, test_size=(1.0 - train_ratio), random_state=42, stratify=y
            )
        except ValueError as exc:
            print("WARNING: Stratified split failed; falling back to unstratified split.")
            print(f"  Reason: {exc}")
            X_train, X_temp, y_train, y_temp = train_test_split(
                X, y, test_size=(1.0 - train_ratio), random_state=42, stratify=None
            )
        val_size = val_ratio / (val_ratio + test_ratio)
        try:
            X_val, X_test, y_val, y_test = train_test_split(
                X_temp, y_temp, test_size=(1.0 - val_size), random_state=42, stratify=y_temp
            )
        except ValueError as exc:
            print("WARNING: Stratified val/test split failed; falling back to unstratified split.")
            print(f"  Reason: {exc}")
            X_val, X_test, y_val, y_test = train_test_split(
                X_temp, y_temp, test_size=(1.0 - val_size), random_state=42, stratify=None
            )
    else:
        # Renormalize train/val ratios for sessions_dir only.
        denom = train_ratio + val_ratio
        if denom <= 0:
            raise ValueError("Train/val ratios must be > 0 when using holdout.")
        normalized_train = train_ratio / denom

        try:
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=(1.0 - normalized_train), random_state=42, stratify=y
            )
        except ValueError as exc:
            print("WARNING: Stratified split failed; falling back to unstratified split.")
            print(f"  Reason: {exc}")
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, test_size=(1.0 - normalized_train), random_state=42, stratify=None
            )

        X_test, y_test, _ = load_sessions(holdout_dir)

    out_dir = project_root / "processed" / "qut_features"
    backup_raw = (args.backup_qut_dir or "").strip()
    if backup_raw and out_dir.is_dir() and (out_dir / "X_train.npy").is_file():
        backup_parent = Path(backup_raw)
        if not backup_parent.is_absolute():
            backup_parent = project_root / backup_parent
        backup_parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_target = backup_parent / f"qut_features_backup_{stamp}"
        shutil.copytree(out_dir, backup_target)
        print("Backed up existing qut_features to:", backup_target)

    ensure_dir(out_dir)

    np.save(out_dir / "X_train.npy", X_train)
    np.save(out_dir / "X_val.npy", X_val)
    np.save(out_dir / "y_train.npy", y_train)
    np.save(out_dir / "y_val.npy", y_val)
    if holdout_dir is None:
        np.save(out_dir / "X_test.npy", X_test)
        np.save(out_dir / "y_test.npy", y_test)

    with open(out_dir / "feature_names.json", "w", encoding="utf-8") as f:
        json.dump(QUT_FEATURE_NAMES, f, indent=2)

    print("Saved QUT feature arrays to:", out_dir)
    if holdout_dir is None:
        print("Train:", X_train.shape, "Val:", X_val.shape, "Test:", X_test.shape)
    else:
        holdout_out = project_root / "processed" / "qut_features_holdout"
        ensure_dir(holdout_out)
        np.save(holdout_out / "X_test.npy", X_test)
        np.save(holdout_out / "y_test.npy", y_test)
        print("Train:", X_train.shape, "Val:", X_val.shape)
        print("Holdout Test:", X_test.shape, "Saved to:", holdout_out)


if __name__ == "__main__":
    main()
