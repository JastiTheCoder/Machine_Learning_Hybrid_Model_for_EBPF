"""
Build a class-balanced eBPF session JSON pool and a stratified train+val / test split.

Reads labeled (or inferable) JSON from:
  - Desktop/capstone_ebpf_repo (sibling of project root by default)
  - Optional extra benign from repo sessions (lodash / benign-test)

Writes copies under data/ebpf_balanced/:
  - pool/           all balanced files (for inspection)
  - train_val_pool/ train+val source (import_sessions --sessions-dir)
  - test_holdout/   held-out test (import_sessions --holdout-dir)

Then run:
  python scripts/import_sessions_to_qut.py \\
    --sessions-dir data/ebpf_balanced/train_val_pool \\
    --holdout-dir data/ebpf_balanced/test_holdout \\
    --blend-qut-dir processed/qut_features \\
    --blend-qut-max 80 \\
    --backup-qut-dir processed/backups
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.import_sessions_to_qut import derive_label


def collect_labeled_json(
    dirs: List[Path], seen_names: set
) -> List[Tuple[Path, int, str]]:
    rows: List[Tuple[Path, int, str]] = []
    for d in dirs:
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.json")):
            if path.name in seen_names:
                continue
            with open(path, "r", encoding="utf-8") as fh:
                record: Dict = json.load(fh)
            label = derive_label(record, path.name)
            rows.append((path, label, path.name))
            seen_names.add(path.name)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build balanced eBPF JSON split")
    parser.add_argument(
        "--extra-benign-dir",
        type=str,
        default="capstone-main(aniruddha_imp)/capstone-main/sessions",
        help="Extra JSON directory for benign samples (lodash, etc.). Empty to skip.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction held out as test (default 0.2)",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for splits",
    )
    args = parser.parse_args()

    ebpf_repo = PROJECT_ROOT.parent / "capstone_ebpf_repo"
    if not ebpf_repo.is_dir():
        raise SystemExit(f"capstone_ebpf_repo not found at {ebpf_repo}")

    seen: set = set()
    rows = collect_labeled_json([ebpf_repo], seen)

    extra = (args.extra_benign_dir or "").strip()
    if extra:
        ed = Path(extra)
        if not ed.is_absolute():
            ed = PROJECT_ROOT / ed
        rows.extend(collect_labeled_json([ed], seen))

    if not rows:
        raise SystemExit("No JSON sessions collected.")

    paths = [p for p, _, _ in rows]
    y = np.array([lab for _, lab, _ in rows], dtype=np.int64)
    benign_idx = np.where(y == 0)[0]
    mal_idx = np.where(y == 1)[0]
    n_b, n_m = len(benign_idx), len(mal_idx)
    print(f"Collected: {len(rows)} files — benign {n_b}, malicious {n_m}")

    if n_m == 0 or n_b == 0:
        raise SystemExit("Need at least one benign and one malicious session to balance.")

    n = min(n_b, n_m)
    rng = np.random.default_rng(args.random_state)
    b_take = rng.choice(benign_idx, size=n, replace=False)
    m_take = rng.choice(mal_idx, size=n, replace=False)
    keep_idx = np.sort(np.concatenate([b_take, m_take]))
    balanced = [(paths[i], int(y[i]), paths[i].name) for i in keep_idx]
    print(f"Balanced pool size: {len(balanced)} ({n} benign + {n} malicious)")

    out_root = PROJECT_ROOT / "data" / "ebpf_balanced"
    pool_dir = out_root / "pool"
    tv_dir = out_root / "train_val_pool"
    ho_dir = out_root / "test_holdout"
    for d in (out_root, pool_dir, tv_dir, ho_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    y_bal = np.array([lab for _, lab, _ in balanced], dtype=np.int64)
    idx = np.arange(len(balanced))
    try:
        tv_idx, te_idx = train_test_split(
            idx,
            test_size=float(args.test_size),
            random_state=args.random_state,
            stratify=y_bal,
        )
    except ValueError as e:
        raise SystemExit(
            f"Stratified test split failed ({e}). "
            "Try more samples per class or a smaller --test-size."
        ) from e

    def copy_many(indices: np.ndarray, dest: Path) -> None:
        for i in indices:
            src, _, name = balanced[int(i)]
            shutil.copy2(src, dest / name)

    copy_many(idx, pool_dir)
    copy_many(tv_idx, tv_dir)
    copy_many(te_idx, ho_dir)

    print("Wrote:")
    print(" ", pool_dir, f"({len(balanced)} files)")
    print(" ", tv_dir, f"({len(tv_idx)} files)")
    print(" ", ho_dir, f"({len(te_idx)} files)")
    print("\nNext (example):")
    print(
        "  python scripts/import_sessions_to_qut.py "
        "--sessions-dir data/ebpf_balanced/train_val_pool "
        "--holdout-dir data/ebpf_balanced/test_holdout "
        "--blend-qut-dir processed/qut_features --blend-qut-max 80 "
        "--backup-qut-dir processed/backups"
    )


if __name__ == "__main__":
    main()
