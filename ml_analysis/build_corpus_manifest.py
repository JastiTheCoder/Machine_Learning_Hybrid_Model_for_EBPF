"""Build an offline family-and-behaviour manifest from captured JSON sessions.

This script never executes npm or malware. It only reads already-captured
session JSON and a local package-list comment file.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd


def read_malware_categories(path: Path) -> dict[str, str]:
    """Read family labels from the category comments in packages-malware.txt."""
    categories: dict[str, str] = {}
    category = "unclassified"

    if not path.exists():
        return categories

    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("# ---"):
            category = line.strip("# -").lower()
            continue
        if line.startswith("#"):
            continue
        package = line.split("#", 1)[0].strip()
        if package:
            categories[package] = category

    return categories


def finding_ids(session: dict) -> list[str]:
    verdict = session.get("verdict") or {}
    findings = verdict.get("findings") or []
    return [
        str(finding.get("rule_id"))
        for finding in findings
        if isinstance(finding, dict) and finding.get("rule_id")
    ]


def name_family(package_name: str, categories: dict[str, str]) -> str:
    if package_name in categories:
        return categories[package_name]
    if package_name.startswith("@"):
        scope = package_name.split("/", 1)[0]
        return f"unknown/scope:{scope}"
    return f"unknown/package:{package_name}"


def behavior_flags(session: dict) -> dict[str, int]:
    verdict = session.get("verdict") or {}
    findings = set(finding_ids(session))
    sensitive = session.get("sensitive") or {}
    tcp = session.get("tcp") or {}
    syscalls = session.get("syscalls") or {}
    process_tree = str(session.get("process_tree") or "")

    return {
        "shell_observed": int(
            any(rule.startswith("PROC-") for rule in findings)
            or "bash(" in process_tree
            or "sh(" in process_tree
        ),
        "network_observed": int(
            any(rule.startswith("NET-") or rule.startswith("DNS-") for rule in findings)
            or int(tcp.get("remote_ips", 0) or 0) > 0
        ),
        "sensitive_file_observed": int(
            any(int(sensitive.get(name, 0) or 0) > 0 for name in (
                "ssh_private_key_read",
                "aws_credentials_read",
                "docker_config_read",
                "kube_config_read",
                "crypto_wallet_read",
                "dotenv_read",
                "gitconfig_read",
                "etc_shadow_read",
            ))
        ),
        "persistence_observed": int(
            int(sensitive.get("persistence_writes", 0) or 0) > 0
            or any(rule.startswith("PERSIST-") for rule in findings)
        ),
        "process_activity_observed": int(
            int(syscalls.get("process_ops", 0) or 0) > 0
            or len(process_tree) > 0
        ),
        "malicious_level": int(verdict.get("level") == "malicious"),
        "suspicious_or_worse": int(
            verdict.get("level") in {"suspicious", "malicious"}
        ),
    }


def load_sessions(directory: Path, label: int) -> list[dict]:
    rows: list[dict] = []
    categories = read_malware_categories(
        Path(__file__).resolve().parents[1] / "scripts" / "capture" / "packages-malware.txt"
    )

    if not directory.exists():
        return rows

    for path in sorted(directory.rglob("*.json")):
        try:
            session = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        package_name = str(session.get("package_name") or path.stem)
        verdict = session.get("verdict") or {}
        flags = behavior_flags(session)

        row = {
            "session_id": session.get("session_id"),
            "package_name": package_name,
            "label": int(session.get("label", label)),
            "origin": "real_malware" if label == 1 else "real_benign",
            "family": name_family(package_name, categories) if label == 1 else "real-benign",
            "schema_version": session.get("schema_version"),
            "verdict_level": verdict.get("level"),
            "verdict_score": verdict.get("score"),
            "finding_ids": ";".join(finding_ids(session)),
            "process_tree": session.get("process_tree"),
            "timed_out": bool(session.get("timed_out", False)),
            "source_file": path.name,
        }
        row.update(flags)
        rows.append(row)

    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign", type=Path, required=True)
    parser.add_argument("--malware", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    rows = load_sessions(args.benign, 0) + load_sessions(args.malware, 1)
    if not rows:
        print("No captured JSON sessions found.")
        return 1

    frame = pd.DataFrame(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.out, index=False)

    print(f"Wrote {len(frame)} session rows to {args.out}")
    print("\nMalware family summary:")
    malware = frame[frame["label"] == 1]
    summary = (
        malware.groupby("family")
        .agg(
            sessions=("session_id", "count"),
            packages=("package_name", "nunique"),
            malicious=("malicious_level", "sum"),
            suspicious_or_worse=("suspicious_or_worse", "sum"),
            shell=("shell_observed", "sum"),
            network=("network_observed", "sum"),
            sensitive=("sensitive_file_observed", "sum"),
            persistence=("persistence_observed", "sum"),
        )
        .sort_values("sessions", ascending=False)
    )
    print(summary.to_string())

    print("\nUnclassified malware rows:", int(
        (malware["family"].str.startswith("unknown/")).sum()
    ))
    print("Malware verdict levels:", dict(Counter(malware["verdict_level"])))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
