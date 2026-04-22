"""
Generate self-explanatory PNG figures for reports and presentations.

Outputs (default): presentation/figures/
  1) report_01_feature_dataset_snapshot.png
  2) report_02_training_metrics.png
  3) report_03_confusion_matrices.png
  4) report_04_ebpf_predictions.png

Run from project root:
  python scripts/generate_report_figures.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# QUT held-out test (30 samples): documented hybrid performance with pure QUT features
QUT_TEST_METRICS = {
    "n_samples": 30,
    "accuracy": 0.9667,
    "precision": 1.0,
    "recall": 0.9333,
    "f1": 0.9655,
    "auc": 0.9422,
    "cm": np.array([[15, 0], [1, 14]], dtype=int),  # rows actual benign, malicious
}


def _fig_title_block(fig, title: str, subtitle: str) -> None:
    fig.suptitle(title, fontsize=14, fontweight="bold", y=0.98)
    fig.text(0.5, 0.93, subtitle, ha="center", fontsize=10, color="#333333", wrap=True)


def figure_feature_snapshot(out_path: Path, n_rows: int = 12) -> None:
    feat_dir = PROJECT_ROOT / "processed" / "qut_features"
    x_path = feat_dir / "X_train.npy"
    names_path = feat_dir / "feature_names.json"
    if not x_path.is_file():
        raise FileNotFoundError(f"Missing {x_path}; run regenerate or import_sessions first.")
    X = np.load(x_path)
    with open(names_path, "r", encoding="utf-8") as fh:
        names = json.load(fh)
    n = min(n_rows, len(X))
    M = X[:n].astype(float)
    # compress scale for heatmap visibility
    V = np.log1p(np.maximum(M, 0))

    short_labels = [f"F{i+1}" for i in range(len(names))]

    fig, ax = plt.subplots(figsize=(14, 6))
    im = ax.imshow(V, aspect="auto", cmap="viridis", interpolation="nearest")
    cbar = plt.colorbar(im, ax=ax, fraction=0.02, pad=0.02)
    cbar.set_label("log(1 + feature value)", fontsize=10)

    ax.set_xticks(np.arange(len(names)))
    ax.set_xticklabels(short_labels, rotation=45, ha="right", fontsize=7)
    ax.set_yticks(np.arange(n))
    ax.set_yticklabels([f"Session {i+1}" for i in range(n)], fontsize=8)
    ax.set_xlabel("QUT-DV25 feature index (see legend below)", fontsize=11)
    ax.set_ylabel("Training samples (first rows of X_train.npy)", fontsize=11)

    fig.text(
        0.5,
        0.02,
        "Columns F1–F36 map to QUT-DV25 names in processed/qut_features/feature_names.json "
        "(e.g. F1=Read_Processes … F36=Pattern_10).",
        ha="center",
        fontsize=9,
        color="#333333",
    )

    _fig_title_block(
        fig,
        "Feature dataset snapshot",
        "Each row is one package install session; each column is one of 36 QUT-DV25 numeric features. "
        "Values shown as log(1+x) for color scale. Source: processed/qut_features/X_train.npy.",
    )
    plt.tight_layout(rect=[0, 0.08, 1, 0.90])
    fig.savefig(out_path, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def figure_training_metrics(out_path: Path) -> None:
    """Two evaluation contexts: QUT test vs eBPF balanced pool (from README / CSV)."""
    rows = [
        ["Metric", "QUT test set\n(30 samples, held out)", "eBPF JSON validation\n(10 balanced sessions)"],
        ["Accuracy", "96.67%", "80.00%"],
        ["Precision (malicious)", "1.00", "0.71"],
        ["Recall (malicious)", "0.93", "1.00"],
        ["F1 (malicious)", "0.97", "0.83"],
        ["ROC AUC", "0.94", "0.60"],
    ]

    fig, ax = plt.subplots(figsize=(11, 4))
    ax.axis("off")
    table = ax.table(
        cellText=rows,
        loc="center",
        cellLoc="center",
        colWidths=[0.22, 0.36, 0.42],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.15, 2.2)
    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_facecolor("#1f4e79")
            cell.get_text().set_color("white")
            cell.get_text().set_fontweight("bold")
        elif col == 0:
            cell.set_facecolor("#e7ecf5")
            cell.get_text().set_fontweight("bold")

    _fig_title_block(
        fig,
        "Training output and evaluation metrics",
        "Left column: hybrid model on QUT-DV25 after training on QUT-only features (typical capstone run). "
        "Right column: same hybrid retrained on blended QUT+eBPF features, then scored on 5 benign + 5 malicious eBPF sessions (balanced pool).",
    )
    plt.tight_layout(rect=[0, 0, 1, 0.88])
    fig.savefig(out_path, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def _plot_cm(ax, cm: np.ndarray, title: str, ylabel: str) -> None:
    im = ax.imshow(cm, cmap="Blues", vmin=0, vmax=max(cm.max(), 1))
    for i in range(2):
        for j in range(2):
            ax.text(j, i, int(cm[i, j]), ha="center", va="center", fontsize=18, color="black")
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Pred benign", "Pred malicious"])
    ax.set_yticklabels(["Actual benign", "Actual malicious"])
    ax.set_ylabel(ylabel, fontsize=10)
    ax.set_title(title, fontsize=12, fontweight="bold")
    plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)


def figure_confusion_matrices(out_path: Path) -> None:
    # eBPF from CSV
    csv_path = PROJECT_ROOT / "processed" / "ebpf_validation_predictions.csv"
    if csv_path.is_file():
        df = pd.read_csv(csv_path)
        y_t = df["true_label"].values
        y_p = df["predicted_label"].values
        tp = int(((y_t == 1) & (y_p == 1)).sum())
        fn = int(((y_t == 1) & (y_p == 0)).sum())
        fp = int(((y_t == 0) & (y_p == 1)).sum())
        tn = int(((y_t == 0) & (y_p == 0)).sum())
        cm_ebpf = np.array([[tn, fp], [fn, tp]], dtype=int)
    else:
        cm_ebpf = np.array([[3, 2], [0, 5]], dtype=int)

    cm_qut = QUT_TEST_METRICS["cm"]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    _plot_cm(
        axes[0],
        cm_qut,
        "QUT held-out test (hybrid)",
        "Counts (n=30)",
    )
    _plot_cm(
        axes[1],
        cm_ebpf,
        "eBPF balanced pool (hybrid)",
        "Counts (n=10)",
    )
    _fig_title_block(
        fig,
        "Confusion matrices",
        "Left: QUT-DV25 test split after training on QUT-only 36-feature data. "
        "Right: eBPF session JSON evaluation (balanced 5 benign + 5 malicious). "
        "Rows = true label, columns = predicted label.",
    )
    plt.tight_layout(rect=[0, 0, 1, 0.88])
    fig.savefig(out_path, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def figure_ebpf_predictions(out_path: Path) -> None:
    csv_path = PROJECT_ROOT / "processed" / "ebpf_validation_predictions.csv"
    if not csv_path.is_file():
        raise FileNotFoundError(f"Missing {csv_path}; run scripts/validate_sessions_with_qut.py first.")

    df = pd.read_csv(csv_path)
    display = df.copy()
    display["file"] = display["filename"].str.replace(".json", "", regex=False)
    display["P(malicious)"] = display["probability"].round(4)
    display["OK"] = display["correct"].map({1: "Yes", 0: "No"})
    cols = ["file", "package_name", "true_label", "predicted_label", "P(malicious)", "OK"]
    display = display[cols]

    fig, ax = plt.subplots(figsize=(14, max(4, 0.45 * len(display) + 2)))
    ax.axis("off")
    table = ax.table(
        cellText=display.values,
        colLabels=cols,
        loc="center",
        cellLoc="left",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.05, 1.8)
    for col in range(len(cols)):
        table[(0, col)].set_facecolor("#1f4e79")
        table[(0, col)].get_text().set_color("white")
        table[(0, col)].get_text().set_fontweight("bold")

    _fig_title_block(
        fig,
        "eBPF session prediction output",
        "Per-session output from validate_sessions_with_qut.py: true label vs hybrid model prediction. "
        "P(malicious) is the LSTM sigmoid score (default threshold 0.5). Source: processed/ebpf_validation_predictions.csv.",
    )
    plt.tight_layout(rect=[0, 0, 1, 0.88])
    fig.savefig(out_path, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate report PNG figures")
    parser.add_argument(
        "--out-dir",
        type=str,
        default="presentation/figures",
        help="Output directory for PNG files",
    )
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = PROJECT_ROOT / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    figure_feature_snapshot(out_dir / "report_01_feature_dataset_snapshot.png")
    print("Wrote", out_dir / "report_01_feature_dataset_snapshot.png")

    figure_training_metrics(out_dir / "report_02_training_metrics.png")
    print("Wrote", out_dir / "report_02_training_metrics.png")

    figure_confusion_matrices(out_dir / "report_03_confusion_matrices.png")
    print("Wrote", out_dir / "report_03_confusion_matrices.png")

    figure_ebpf_predictions(out_dir / "report_04_ebpf_predictions.png")
    print("Wrote", out_dir / "report_04_ebpf_predictions.png")

    print("\nAll figures saved under:", out_dir)


if __name__ == "__main__":
    main()
