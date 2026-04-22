"""
Import npm-ebpf-monitor session JSON files and emit QUT feature arrays.

This script converts session JSON (aggregated features) into the exact
36-feature QUT layout expected by the hybrid model.
"""

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.qut_feature_extractor import QUT_FEATURE_NAMES


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
        # TCP (5)
        float(tcp.get("state_transitions", 0)),
        float(tcp.get("local_ips", 0)),
        float(tcp.get("remote_ips", 0)),
        float(tcp.get("local_ports", 0)),
        float(tcp.get("remote_ports", 0)),
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


def load_sessions(sessions_dir: Path) -> Tuple[np.ndarray, np.ndarray, List[Dict]]:
    """Load session JSON files and return features, labels, and metadata.

    Labels are taken only from the JSON `label` field. Sessions without
    integer labels are skipped.
    """
    rows: List[List[float]] = []
    labels: List[int] = []
    meta: List[Dict] = []
    skipped = 0

    for path in sorted(sessions_dir.glob("*.json")):
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
                "label": label,
            }
        )

    if not rows:
        raise RuntimeError(f"No labeled session JSON files found in {sessions_dir}")

    if skipped > 0:
        print(f"WARN: skipped {skipped} sessions without integer label field")

    x = np.asarray(rows, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int64)
    return x, y, meta


def write_qut_csv(sessions_dir: Path, csv_path: Path) -> None:
    """Write a 39-column CSV (package_name + label + 36 features + severity_score)."""
    header = ["package_name", "label"] + QUT_FEATURE_NAMES + ["severity_score"]

    rows: List[List[str]] = []
    skipped = 0
    for path in sorted(sessions_dir.glob("*.json")):
        with open(path, "r", encoding="utf-8") as f:
            record = json.load(f)

        label = record.get("label", None)
        if not isinstance(label, int):
            skipped += 1
            continue

        features = extract_feature_vector(record)
        package_name = record.get("package_name", path.name)
        severity_score = label

        rows.append(
            [str(package_name), str(label)] + [str(v) for v in features] + [str(severity_score)]
        )

    if not rows:
        raise RuntimeError(f"No labeled session JSON files found in {sessions_dir}")

    if skipped > 0:
        print(f"WARN: skipped {skipped} sessions without integer label field")

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
        default="sessions",
        help="Path to npm-ebpf-monitor sessions directory",
    )
    parser.add_argument(
        "--csv-out",
        type=str,
        default="",
        help="Optional path to write a 39-column CSV for sessions-dir",
    )
    args = parser.parse_args()

    sessions_dir = Path(args.sessions_dir)
    if not sessions_dir.is_absolute():
        sessions_dir = PROJECT_ROOT / sessions_dir

    if args.csv_out:
        csv_path = Path(args.csv_out)
        if not csv_path.is_absolute():
            csv_path = PROJECT_ROOT / csv_path
        write_qut_csv(sessions_dir, csv_path)
        print("Saved 39-column CSV to:", csv_path)

    x, y, _ = load_sessions(sessions_dir)
    print("Loaded sessions:", x.shape, "Labels:", y.shape)


if __name__ == "__main__":
    main()
