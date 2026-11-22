"""
Train and evaluate on natively captured npm sessions.
=====================================================

Replaces train_on_qut.py, which is superseded (see QUT_RETIREMENT.md). Every
sample here is captured by our own monitor, on npm, under one measurement
methodology, so the sign-inversion and scale problems that killed the
cross-ecosystem experiment do not arise.

The script runs up to three experiments and is deliberate about which number
is the honest one:

  A. GENERALISATION (the headline result)
     Train on real benign packages plus the synthetic malicious fixtures.
     Test on held-out real benign packages plus REAL malware.
     This answers the actual question: does a detector taught on fixtures we
     wrote ourselves catch malware we did not write?

  B. SYNTHETIC-ONLY (a secondary, much easier check)
     Cross-validation within the synthetic corpus. Reported separately and
     labelled as easier, because the synthetic packages are louder than real
     malware and share a single authoring template.

  C. POOLED (only when there is enough real malware)
     A stratified split with real malware on both sides. Gives a more
     conventional number once the corpus can support it.

Usage:
    python train_native.py \
        --benign   ../captures/benign \
        --malware  ../captures/malware \
        --synthetic ../sessions

Any directory may be omitted; the script reports which experiments it can and
cannot run rather than guessing.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    average_precision_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    GroupShuffleSplit,
    StratifiedKFold,
    StratifiedGroupKFold,
    cross_val_predict,
    train_test_split,
)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

try:
    from xgboost import XGBClassifier

    HAS_XGB = True
except ImportError:
    HAS_XGB = False

RANDOM_STATE = 42
OUTPUT_DIR = Path(__file__).parent / "outputs"

# Minimum real-malware samples before Experiment C is meaningful. Below this a
# stratified split puts single-digit counts in the test fold, where one sample
# moves recall by more than ten points.
MIN_REAL_MALWARE_FOR_POOLED = 20

# Columns that must never be features.
#
# severity_score is a verbatim copy of the label. verdict_* is derived by the
# same rule engine whose output assign_label() in feature_analysis.py uses to
# label sessions, so feeding it back in is circular. Both produce excellent,
# meaningless scores.
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

# Fallback labels for sessions captured before the harness started stamping
# .label into the JSON.
LEGACY_LABEL_RULES = {
    "benign-test": 0,
    "lodash": 0,
    "underscore": 0,
    "moment": 0,
    "chalk": 0,
    "axios": 0,
    "uuid": 0,
    "dotenv": 0,
    "debug": 0,
    "suspicious-test": 1,
    "env-stealer": 1,
    "ssh-reader": 1,
    "reverse-shell": 1,
    "persistence-test": 1,
    "crypto-miner": 1,
}

SYNTHETIC_MARKERS = ("-test", "benign-test", "suspicious-test")


def family_group_key(package_name: str) -> str:
    """Use package identity as the smallest safe group key.

    Repeated versions of the same package must not cross a train/test boundary.
    This is intentionally conservative and is less precise than a confirmed
    malware-family mapping, which should be added from capture provenance.
    """
    name = (package_name or "").strip()
    if name.startswith("@") and "/" in name:
        scope, remainder = name.split("/", 1)
        return scope + "/" + remainder.rsplit("@", 1)[0]
    if "@" in name and not name.startswith("@"):
        return name.rsplit("@", 1)[0]
    return name or "unknown"


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def flatten(session: dict) -> dict:
    """Flatten one session JSON into a single-level feature dict."""
    flat = {
        "session_id": session.get("session_id"),
        "package_name": session.get("package_name", ""),
        "schema_version": session.get("schema_version", "1.0.0"),
        "capture_source": session.get("capture_source", ""),
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
                flat[f"{prefix}_{key}"] = value

    verdict = session.get("verdict") or {}
    flat["verdict_score"] = verdict.get("score", 0)
    flat["verdict_level"] = verdict.get("level", "none")

    flat["label"] = session.get("label")
    return flat


def resolve_package_name(recorded: str, filename_stem: str, session_id: str) -> str:
    """Return the most usable package name for a session.

    detector.go records "unknown" when it cannot parse the install target from
    the exec arguments, which happens often enough to matter -- four of the
    malicious fixture sessions in ./sessions are affected. The filename still
    carries the real name, because json_writer.go builds it as
    "{session_id}_{package_name}.json".

    Falling back matters more than it looks: without it those four sessions
    fail every label rule, get excluded as unlabelled, and the malicious class
    quietly loses most of its members while the script reports success.
    """
    recorded = (recorded or "").strip()
    if recorded and recorded != "unknown":
        return recorded

    stem = filename_stem
    prefix = f"{session_id}_"
    if session_id and stem.startswith(prefix):
        stem = stem[len(prefix):]
    return stem


def infer_legacy_label(package_name: str):
    for marker, label in LEGACY_LABEL_RULES.items():
        if marker in package_name:
            return label
    return None


def is_synthetic(package_name: str) -> bool:
    return any(marker in package_name for marker in SYNTHETIC_MARKERS)


def load_directory(path: Path, origin_hint: str | None) -> list[dict]:
    """Load every session JSON under path, tagging each with an origin."""
    if not path.exists():
        print(f"  {path}: does not exist, skipped")
        return []

    rows = []
    unlabelled = []

    for f in sorted(path.rglob("*.json")):
        try:
            session = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"  SKIP {f.name}: {exc}")
            continue

        row = flatten(session)
        name = resolve_package_name(row["package_name"], f.stem, row["session_id"] or "")
        row["package_name"] = name
        row["family_group"] = family_group_key(name)

        if row["label"] is None:
            row["label"] = infer_legacy_label(name)
        if row["label"] is None:
            unlabelled.append(f.name)
            continue

        synthetic = is_synthetic(name)
        if origin_hint is not None:
            row["origin"] = origin_hint
        elif synthetic:
            row["origin"] = "synthetic_malicious" if row["label"] == 1 else "synthetic_benign"
        else:
            row["origin"] = "real_malware" if row["label"] == 1 else "real_benign"

        row["source_file"] = f.name
        rows.append(row)

    print(f"  {path}: {len(rows)} session(s) loaded")
    if unlabelled:
        # Refused rather than defaulted. A defaulted label is what put genuinely
        # malicious sessions into the training set marked benign (AUDIT.md C4).
        print(f"    EXCLUDED {len(unlabelled)} unlabelled session(s): {', '.join(unlabelled[:5])}"
              + (" ..." if len(unlabelled) > 5 else ""))

    return rows


# ---------------------------------------------------------------------------
# Feature selection
# ---------------------------------------------------------------------------
def select_features(df: pd.DataFrame) -> list[str]:
    """Return usable numeric feature columns, explaining every exclusion."""
    candidates = [
        c for c in df.columns
        if c not in LEAKY_COLUMNS
        and c != "source_file"
        and pd.api.types.is_numeric_dtype(df[c])
    ]

    # Pattern columns changed meaning in schema 1.2.0: they counted exactly
    # consecutive syscall triplets before, and gap-tolerant ones after. Pooling
    # the two puts incomparable values in one column.
    schemas = set(df["schema_version"])
    pre_12 = {s for s in schemas if s < "1.2.0"}
    if pre_12 and len(schemas) > 1:
        dropped = [c for c in candidates if c.startswith("pat_")]
        candidates = [c for c in candidates if not c.startswith("pat_")]
        print(f"  Dropped {len(dropped)} pattern column(s): corpus mixes schema "
              f"{sorted(schemas)} and p1-p10 are not comparable across 1.2.0")

        # Sensitive columns and the legacy uppercase TCP aliases were not
        # present in every capture. Mixing zero-filled legacy records with
        # native 1.2.0 records would make "missing" look like a feature.
        incompatible = [
            c for c in candidates
            if c.startswith("sens_") or c in {
                "tcp_StateTransitions", "tcp_LocalIPs", "tcp_RemoteIPs",
                "tcp_LocalPorts", "tcp_RemotePorts",
                "os_ssh_aws_wallet_access",
            }
        ]
        candidates = [c for c in candidates if c not in incompatible]
        if incompatible:
            print(f"  Dropped {len(incompatible)} schema-incompatible column(s): "
                  + ", ".join(incompatible[:8])
                  + (" ..." if len(incompatible) > 8 else ""))

    # A column that never varies cannot separate anything, and constant columns
    # mostly indicate a feature the monitor is not populating.
    constant = [c for c in candidates if df[c].nunique(dropna=False) <= 1]
    if constant:
        candidates = [c for c in candidates if c not in constant]
        print(f"  Dropped {len(constant)} constant column(s): {', '.join(constant[:8])}"
              + (" ..." if len(constant) > 8 else ""))

    return candidates


def warn_about_missing_sensitive(df: pd.DataFrame) -> None:
    sens_cols = [c for c in df.columns if c.startswith("sens_")]
    if not sens_cols:
        print("\n  WARNING: no sensitive block in any session. The monitor predates")
        print("  schema 1.2.0, so credential-path signal is absent. Rebuild it.")
        return

    missing = df[sens_cols].isna().all(axis=1).sum()
    if missing:
        print(f"\n  WARNING: {missing} session(s) have no sensitive block and read as")
        print("  all-zero, which is indistinguishable from a genuinely clean session.")
        print("  Re-capture them rather than training on the mixture.")


def audit_features(df: pd.DataFrame, features: list[str]) -> None:
    """Fail loudly on identifiers and label-derived columns reaching features."""
    prohibited = sorted(set(features).intersection(LEAKY_COLUMNS))
    if prohibited:
        raise RuntimeError(
            "Leakage audit failed: prohibited columns are model features: "
            + ", ".join(prohibited)
        )

    identifier_like = [c for c in features if any(
        token in c.lower()
        for token in ("session_id", "package_name", "capture_source", "source_file")
    )]
    if identifier_like:
        raise RuntimeError(
            "Leakage audit failed: identifier-like columns are model features: "
            + ", ".join(identifier_like)
        )

    missing = df[features].isna().sum()
    missing = missing[missing > 0].sort_values(ascending=False)
    if not missing.empty:
        print("\n  Missing-value audit:")
        for column, count in missing.head(12).items():
            print(f"    {column}: {int(count)} missing")

    print("  Leakage audit: prohibited columns and identifiers absent")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
def build_models(n_positive: int, n_negative: int) -> dict:
    """Return the model set, weighted for the class imbalance actually present.

    The malicious class is the small one in every experiment here, so an
    unweighted model can score well by predicting "benign" for everything --
    which is exactly what the QUT-trained models did, at 72.73% accuracy and
    0% recall. Every model below is weighted.

    A logistic baseline is included on purpose. On a corpus this small, trees
    beating it by a wide margin usually means memorisation rather than a
    genuinely non-linear boundary.
    """
    models = {
        "LogisticRegression": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=2000, class_weight="balanced",
                               random_state=RANDOM_STATE),
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced",
            random_state=RANDOM_STATE, n_jobs=-1,
        ),
    }

    if HAS_XGB:
        # scale_pos_weight is XGBoost's equivalent of class_weight='balanced':
        # the ratio of negative to positive examples.
        ratio = (n_negative / n_positive) if n_positive else 1.0
        models["XGBoost"] = XGBClassifier(
            n_estimators=300, max_depth=4, learning_rate=0.1,
            scale_pos_weight=max(1.0, ratio),
            eval_metric="logloss", random_state=RANDOM_STATE,
        )

    return models


def evaluate(name: str, y_true, y_pred, y_score) -> dict:
    print(f"\n  --- {name} ---")
    print(classification_report(y_true, y_pred, target_names=["benign", "malicious"],
                                zero_division=0, digits=3))

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    print(f"  confusion matrix (rows=true, cols=pred):\n"
          f"      benign   [{cm[0][0]:4d} {cm[0][1]:4d}]\n"
          f"      malicious[{cm[1][0]:4d} {cm[1][1]:4d}]")

    auc = None
    pr_auc = None
    if y_score is not None and len(set(y_true)) == 2:
        auc = roc_auc_score(y_true, y_score)
        print(f"  ROC AUC: {auc:.3f}"
              + ("   (below 0.5 means the ranking is inverted)" if auc < 0.5 else ""))
        pr_auc = average_precision_score(y_true, y_score)
        print(f"  PR-AUC (average precision): {pr_auc:.3f}")
        precision, recall, thresholds = precision_recall_curve(y_true, y_score)
        print(f"  PR operating points:")
        for recall_target in (0.25, 0.50, 0.75):
            eligible = [i for i, r in enumerate(recall)
                        if r >= recall_target]
            if eligible:
                i = eligible[-1]
                threshold = thresholds[i] if i < len(thresholds) else 0.0
                print(f"    recall >= {recall_target:.2f}: "
                      f"precision={precision[i]:.3f}, threshold={threshold:.3f}")

    tp = cm[1][1]
    fn = cm[1][0]
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    return {"model": name, "recall_malicious": recall, "roc_auc": auc,
            "pr_auc": pr_auc, "tp": tp, "fn": fn,
            "fp": cm[0][1], "tn": cm[0][0]}


def select_validation_threshold(y_validation, y_score, target_fpr=0.01):
    """Choose the lowest score threshold that does not exceed target FPR.

    This function is used only on a validation partition. A caller must not
    use it on the frozen final test partition.
    """
    candidates = sorted(set(float(v) for v in y_score), reverse=True)
    best = (1.0, 0.0)
    for threshold in candidates:
        pred = (y_score >= threshold).astype(int)
        cm = confusion_matrix(y_validation, pred, labels=[0, 1])
        fp = cm[0][1]
        tn = cm[0][0]
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        tp = cm[1][1]
        fn = cm[1][0]
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        if fpr <= target_fpr and recall >= best[1]:
            best = (threshold, recall)
    threshold, recall = best
    pred = (y_score >= threshold).astype(int)
    cm = confusion_matrix(y_validation, pred, labels=[0, 1])
    fp = cm[0][1]
    tn = cm[0][0]
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return threshold, recall, fpr


# ---------------------------------------------------------------------------
# Experiments
# ---------------------------------------------------------------------------
def experiment_generalisation(df: pd.DataFrame, features: list[str]) -> pd.DataFrame | None:
    print("\n" + "=" * 70)
    print(" EXPERIMENT A -- generalisation to real malware  [headline result]")
    print("=" * 70)

    real_benign = df[df.origin == "real_benign"]
    real_malware = df[df.origin == "real_malware"]
    synth_mal = df[df.origin == "synthetic_malicious"]

    missing = []
    if len(real_benign) < 20:
        missing.append(f"real benign (have {len(real_benign)}, want >= 20)")
    if len(real_malware) < 5:
        missing.append(f"real malware (have {len(real_malware)}, want >= 5)")
    if len(synth_mal) < 3:
        missing.append(f"synthetic malicious (have {len(synth_mal)}, want >= 3)")

    if missing:
        print("\n  Cannot run. Missing: " + "; ".join(missing))
        print("  Capture the corpus first: see scripts/capture/README.md")
        return None

    # Hold out real benign packages for validation and final testing. Package
    # identities remain together so repeated captures cannot leak across them.
    benign = real_benign.copy()
    benign["family_group"] = benign["family_group"].fillna("unknown")
    benign_groups = benign["family_group"].unique()
    train_groups, heldout_groups = train_test_split(
        benign_groups, test_size=0.40, random_state=RANDOM_STATE
    )
    heldout = benign[benign["family_group"].isin(heldout_groups)]
    benign_train = benign[benign["family_group"].isin(train_groups)]

    heldout_groups = heldout["family_group"].unique()
    if len(heldout_groups) < 2:
        print("\n  Cannot create separate benign validation/test groups.")
        return None
    validation_groups, test_groups = train_test_split(
        heldout_groups, test_size=0.50, random_state=RANDOM_STATE
    )
    benign_validation = heldout[heldout["family_group"].isin(validation_groups)]
    benign_test = heldout[heldout["family_group"].isin(test_groups)]

    # Synthetic malicious validation is used only to select an operating
    # threshold. It is not used for threshold selection against real malware.
    synth_mal = synth_mal.copy()
    synth_mal["family_group"] = synth_mal["family_group"].fillna("unknown")
    synth_groups = synth_mal["family_group"].unique()
    if len(synth_groups) >= 2:
        synth_train_groups, synth_validation_groups = train_test_split(
            synth_groups, test_size=0.50, random_state=RANDOM_STATE
        )
        synth_train = synth_mal[synth_mal["family_group"].isin(synth_train_groups)]
        synth_validation = synth_mal[
            synth_mal["family_group"].isin(synth_validation_groups)
        ]
    else:
        synth_train = synth_mal
        synth_validation = synth_mal

    train = pd.concat([benign_train, synth_train])
    validation = pd.concat([benign_validation, synth_validation])
    test = pd.concat([benign_test, real_malware])

    print(f"\n  Train: {len(benign_train)} real benign + {len(synth_train)} synthetic malicious")
    print(f"  Validation: {len(benign_validation)} real benign + "
          f"{len(synth_validation)} synthetic malicious")
    print(f"  Test:  {len(benign_test)} real benign + {len(real_malware)} REAL malware")
    print("\n  No real malware is in the training set, by design. Recall below is")
    print("  the generalisation number -- detection of attacks we did not author.")

    X_train, y_train = train[features].fillna(0), train["label"].astype(int)
    X_validation, y_validation = (
        validation[features].fillna(0),
        validation["label"].astype(int),
    )
    X_test, y_test = test[features].fillna(0), test["label"].astype(int)

    partition_manifest = pd.concat([
        train.assign(partition="train"),
        validation.assign(partition="validation"),
        test.assign(partition="test"),
    ], ignore_index=True)
    manifest_columns = [
        c for c in (
            "session_id", "package_name", "family_group", "origin",
            "source_file", "label", "partition",
        )
        if c in partition_manifest.columns
    ]
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest_path = OUTPUT_DIR / "generalisation_partition_manifest.csv"
    partition_manifest[manifest_columns].to_csv(manifest_path, index=False)
    print(f"  Wrote frozen partition manifest: {manifest_path}")

    n_pos, n_neg = int(y_train.sum()), int(len(y_train) - y_train.sum())

    results = []
    fitted = {}
    for name, model in build_models(n_pos, n_neg).items():
        model.fit(X_train, y_train)
        fitted[name] = model
        y_validation_score = (model.predict_proba(X_validation)[:, 1]
                              if hasattr(model, "predict_proba") else None)
        y_test_score = (model.predict_proba(X_test)[:, 1]
                   if hasattr(model, "predict_proba") else None)
        y_pred = model.predict(X_test)
        y_score = y_test_score

        calibrated_result = {}
        if y_validation_score is not None:
            threshold, val_recall, val_fpr = select_validation_threshold(
                y_validation, y_validation_score, target_fpr=0.01
            )
            y_calibrated_pred = (y_test_score >= threshold).astype(int)
            print(f"\n  --- {name}: validation-calibrated threshold at <=1% FPR ---")
            print(f"  Validation threshold: {threshold:.6f}")
            print(f"  Validation recall/FPR: {val_recall:.3f}/{val_fpr:.3f}")
            cm = confusion_matrix(y_test, y_calibrated_pred, labels=[0, 1])
            tp = cm[1][1]
            fn = cm[1][0]
            fp = cm[0][1]
            tn = cm[0][0]
            recall = tp / (tp + fn) if (tp + fn) else float("nan")
            print(f"  Frozen-test TP/FN/FP/TN: {tp}/{fn}/{fp}/{tn}")
            print(f"  Frozen-test recall: {recall:.3f}")
            calibrated_result = {
                "calibrated_threshold": threshold,
                "validation_recall": val_recall,
                "validation_fpr": val_fpr,
                "calibrated_recall": recall,
                "calibrated_tp": tp,
                "calibrated_fn": fn,
                "calibrated_fp": fp,
                "calibrated_tn": tn,
            }
        result = evaluate(name, y_test, y_pred, y_score)
        result.update(calibrated_result)
        results.append(result)

    report_importances(fitted.get("RandomForest"), features, "experiment_a")
    return pd.DataFrame(results)


def experiment_synthetic_only(df: pd.DataFrame, features: list[str]) -> pd.DataFrame | None:
    print("\n" + "=" * 70)
    print(" EXPERIMENT B -- synthetic corpus only  [secondary, easier target]")
    print("=" * 70)

    subset = df[df.origin.isin(["synthetic_benign", "synthetic_malicious", "real_benign"])]
    y = subset["label"].astype(int)

    if y.nunique() < 2 or y.sum() < 3 or (len(y) - y.sum()) < 3:
        print(f"\n  Cannot run: need at least 3 of each class, have "
              f"{int(y.sum())} malicious / {int(len(y) - y.sum())} benign")
        return None

    print(f"\n  {len(subset)} sessions, {int(y.sum())} malicious. Stratified 5-fold CV.")
    print("  Treat this as a pipeline smoke test, not an evaluation. The synthetic")
    print("  packages are louder than real malware and share one authoring template,")
    print("  so any feature separating that template from a real library reads as a")
    print("  malware signal.")

    X = subset[features].fillna(0)
    n_splits = min(5, int(y.sum()), int(len(y) - y.sum()))
    groups = subset["family_group"].fillna("unknown")
    try:
        cv = StratifiedGroupKFold(
            n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE
        )
        cv_split = cv.split(X, y, groups=groups)
    except (TypeError, ValueError):
        cv = StratifiedKFold(
            n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE
        )
        cv_split = cv.split(X, y)

    results = []
    for name, model in build_models(int(y.sum()), int(len(y) - y.sum())).items():
        cv_split = cv.split(X, y, groups=groups) if isinstance(cv, StratifiedGroupKFold) else cv.split(X, y)
        y_pred = cross_val_predict(model, X, y, cv=cv_split)
        cv_split = cv.split(X, y, groups=groups) if isinstance(cv, StratifiedGroupKFold) else cv.split(X, y)
        try:
            y_score = cross_val_predict(model, X, y, cv=cv_split, method="predict_proba")[:, 1]
        except (AttributeError, ValueError):
            y_score = None
        results.append(evaluate(name, y, y_pred, y_score))

    return pd.DataFrame(results)


def experiment_pooled(df: pd.DataFrame, features: list[str]) -> pd.DataFrame | None:
    print("\n" + "=" * 70)
    print(" EXPERIMENT C -- pooled stratified split")
    print("=" * 70)

    real_malware = df[df.origin == "real_malware"]
    if len(real_malware) < MIN_REAL_MALWARE_FOR_POOLED:
        print(f"\n  Skipped: {len(real_malware)} real malware samples, need "
              f"{MIN_REAL_MALWARE_FOR_POOLED}.")
        print("  Below that, one test sample moves recall by more than ten points and")
        print("  the number would be noise presented as a result.")
        return None

    y = df["label"].astype(int)
    X = df[features].fillna(0)
    groups = df["family_group"].fillna("unknown")
    split = GroupShuffleSplit(
        n_splits=1, test_size=0.25, random_state=RANDOM_STATE
    )
    train_index, test_index = next(split.split(X, y, groups=groups))
    X_train, X_test = X.iloc[train_index], X.iloc[test_index]
    y_train, y_test = y.iloc[train_index], y.iloc[test_index]

    print(f"\n  Train {len(X_train)} / Test {len(X_test)}, "
          f"package identities held together when possible.")

    n_pos, n_neg = int(y_train.sum()), int(len(y_train) - y_train.sum())

    results = []
    for name, model in build_models(n_pos, n_neg).items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_score = (model.predict_proba(X_test)[:, 1]
                   if hasattr(model, "predict_proba") else None)
        results.append(evaluate(name, y_test, y_pred, y_score))

    return pd.DataFrame(results)


def report_importances(model, features: list[str], tag: str) -> None:
    if model is None or not hasattr(model, "feature_importances_"):
        return

    imp = (pd.Series(model.feature_importances_, index=features)
           .sort_values(ascending=False))

    print("\n  Top 15 features (RandomForest):")
    for feat, val in imp.head(15).items():
        print(f"      {val:.4f}  {feat}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUTPUT_DIR / f"native_importances_{tag}.csv"
    imp.to_frame("importance").to_csv(out)
    print(f"\n  Written: {out}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--benign", type=Path, help="directory of real benign captures")
    parser.add_argument("--malware", type=Path, help="directory of real malware captures")
    parser.add_argument("--synthetic", type=Path,
                        help="directory of synthetic fixture sessions (e.g. ./sessions)")
    parser.add_argument("--family-manifest", type=Path,
                        help="optional CSV mapping session_id to family")
    args = parser.parse_args()

    if not any([args.benign, args.malware, args.synthetic]):
        parser.error("supply at least one of --benign, --malware, --synthetic")

    print("=" * 70)
    print(" Training on natively captured npm sessions")
    print("=" * 70)
    print("\nLoading:")

    rows = []
    if args.benign:
        rows += load_directory(args.benign, "real_benign")
    if args.malware:
        rows += load_directory(args.malware, "real_malware")
    if args.synthetic:
        rows += load_directory(args.synthetic, None)

    if not rows:
        print("\nNo labelled sessions found. Nothing to do.")
        return 1

    df = pd.DataFrame(rows)

    if args.family_manifest:
        if not args.family_manifest.exists():
            print(f"\nFamily manifest not found: {args.family_manifest}")
            return 1
        manifest = pd.read_csv(args.family_manifest)
        required = {"session_id", "family"}
        if not required.issubset(manifest.columns):
            print("\nFamily manifest must contain session_id and family columns.")
            return 1
        family_map = (
            manifest.drop_duplicates("session_id")
            .set_index("session_id")["family"]
            .to_dict()
        )
        df["family_group"] = [
            str(family_map[session_id])
            if str(origin) == "real_malware" and session_id in family_map
            else str(family_group)
            for session_id, origin, family_group in zip(
                df["session_id"], df["origin"], df["family_group"]
            )
        ]
        print(f"\nApplied family manifest: {args.family_manifest}")

    print("\nCorpus composition:")
    for origin, count in sorted(Counter(df["origin"]).items()):
        print(f"  {origin:22s} {count:4d}")
    print(f"  {'TOTAL':22s} {len(df):4d}   "
          f"({int(df.label.sum())} malicious, {int(len(df) - df.label.sum())} benign)")

    print("\nFeature selection:")
    warn_about_missing_sensitive(df)
    features = select_features(df)
    print(f"  Using {len(features)} features")
    audit_features(df, features)

    sens_used = [f for f in features if f.startswith("sens_")]
    if sens_used:
        print(f"  Including {len(sens_used)} sensitive-access features (new in schema 1.2.0)")

    if not features:
        print("\nNo usable features. Stopping.")
        return 1

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_DIR / "native_corpus_flattened.csv", index=False)

    results = {}
    for tag, fn in (("A_generalisation", experiment_generalisation),
                    ("B_synthetic_only", experiment_synthetic_only),
                    ("C_pooled", experiment_pooled)):
        out = fn(df, features)
        if out is not None:
            out.insert(0, "experiment", tag)
            results[tag] = out

    print("\n" + "=" * 70)
    print(" SUMMARY")
    print("=" * 70)

    if not results:
        print("\n  No experiment could run with the current corpus.")
        print("  Capture data first: scripts/capture/README.md")
        return 1

    combined = pd.concat(results.values(), ignore_index=True)
    print()
    print(combined.to_string(index=False))

    out = OUTPUT_DIR / "native_results.csv"
    combined.to_csv(out, index=False)
    print(f"\n  Written: {out}")

    if "A_generalisation" in results:
        print("\n  Quote Experiment A in the report. B is an easier target and C, when")
        print("  present, has real malware in training and so does not answer the")
        print("  generalisation question.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
