"""
Feature Diagnostics for QUT -> npm Transfer
============================================
Answers one question: which of the 37 features are actually safe to train on
QUT and apply to npm?

A feature is unsafe if it is constant in either domain, or if the two domains
report values on wildly different scales. Both cases inject a fixed, meaningless
coordinate into every npm sample after QUT-fitted scaling, which is the
suspected cause of the 0% malicious recall in train_on_qut.py.

Outputs:
  outputs/feature_diagnostics.csv  - per-feature verdict table
  stdout                           - readable report + recommended whitelist
"""

import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.preprocessing import StandardScaler
import warnings

warnings.filterwarnings("ignore")

from train_on_qut import load_qut_dataset, get_common_features, prepare_features

NPM_SESSIONS = Path(__file__).parent / "outputs" / "sessions_flattened.csv"
OUTPUT_DIR = Path(__file__).parent / "outputs"

# A feature whose domain medians differ by more than this factor is treated as
# measuring different things under the same name.
SCALE_MISMATCH_FACTOR = 10.0

# Conventional Cohen's d thresholds.
D_LARGE = 0.8
D_SMALL = 0.2


def cohens_d(group_a, group_b):
    """Standardised mean difference between two groups.

    Returns 0.0 when both groups are degenerate, so a dead feature scores as
    'no separation' rather than blowing up on a zero denominator.
    """
    n_a, n_b = len(group_a), len(group_b)
    if n_a < 2 or n_b < 2:
        return 0.0

    var_a, var_b = np.var(group_a, ddof=1), np.var(group_b, ddof=1)
    pooled = np.sqrt(((n_a - 1) * var_a + (n_b - 1) * var_b) / (n_a + n_b - 2))
    if pooled == 0:
        return 0.0
    return (np.mean(group_b) - np.mean(group_a)) / pooled


def load_npm():
    df = pd.read_csv(NPM_SESSIONS)
    df["label_numeric"] = (df["label"] == "malicious").astype(int)
    return df


def column(df, feat):
    """Numeric column, or an all-zero column if the feature is absent."""
    if feat in df.columns:
        return pd.to_numeric(df[feat], errors="coerce").fillna(0)
    return pd.Series(np.zeros(len(df)), index=df.index)


def build_diagnostics(npm_df, qut_df, features):
    """One row per feature describing its health in each domain."""
    npm_benign_mask = npm_df["label_numeric"] == 0
    npm_malicious_mask = npm_df["label_numeric"] == 1
    qut_benign_mask = qut_df["label"] == 0
    qut_malicious_mask = qut_df["label"] == 1

    rows = []
    for feat in features:
        npm_vals = column(npm_df, feat)
        qut_vals = column(qut_df, feat)

        benign = npm_vals[npm_benign_mask].values
        malicious = npm_vals[npm_malicious_mask].values

        npm_dead = npm_vals.nunique() <= 1
        qut_dead = qut_vals.nunique() <= 1

        # Median ratio is the scale check; medians resist the heavy tails in
        # syscall counts far better than means.
        npm_med, qut_med = np.median(npm_vals), np.median(qut_vals)
        if npm_med == 0 and qut_med == 0:
            scale_ratio = 1.0
        elif qut_med == 0 or npm_med == 0:
            scale_ratio = np.inf
        else:
            scale_ratio = max(npm_med / qut_med, qut_med / npm_med)

        d_npm = cohens_d(benign, malicious)
        d_qut = cohens_d(qut_vals[qut_benign_mask].values,
                         qut_vals[qut_malicious_mask].values)

        # Sign encodes which class runs higher. If the two domains disagree,
        # a rule learned on QUT fires backwards on npm.
        if abs(d_npm) < D_SMALL or abs(d_qut) < D_SMALL:
            direction = "weak"
        elif np.sign(d_npm) == np.sign(d_qut):
            direction = "AGREE"
        else:
            direction = "CONFLICT"

        if npm_dead and qut_dead:
            verdict = "DEAD_BOTH"
        elif npm_dead:
            verdict = "DEAD_NPM"
        elif qut_dead:
            verdict = "DEAD_QUT"
        elif scale_ratio > SCALE_MISMATCH_FACTOR:
            verdict = "SCALE_MISMATCH"
        else:
            verdict = "TRANSFERABLE"

        rows.append({
            "feature": feat,
            "verdict": verdict,
            "direction": direction,
            "npm_benign_mean": np.mean(benign) if len(benign) else 0.0,
            "npm_malicious_mean": np.mean(malicious) if len(malicious) else 0.0,
            "cohens_d": d_npm,
            "abs_cohens_d": abs(d_npm),
            "cohens_d_qut": d_qut,
            "abs_cohens_d_qut": abs(d_qut),
            "npm_median": npm_med,
            "qut_median": qut_med,
            "scale_ratio": scale_ratio,
            "npm_min": npm_vals.min(),
            "npm_max": npm_vals.max(),
            "qut_min": qut_vals.min(),
            "qut_max": qut_vals.max(),
        })

    return pd.DataFrame(rows)


def report_npm_health(diag):
    print("\n" + "=" * 78)
    print("PART 1: NPM FEATURE HEALTH")
    print("=" * 78)

    dead = diag[diag["verdict"].isin(["DEAD_NPM", "DEAD_BOTH"])]
    print(f"\nDead in npm (constant across all sessions): {len(dead)} of {len(diag)}")
    print("These contribute nothing but still occupy a slot in the feature vector.\n")
    for _, r in dead.iterrows():
        print(f"  {r['feature']:<24} constant at {r['npm_min']:.0f}")

    alive = diag[~diag["verdict"].isin(["DEAD_NPM", "DEAD_BOTH"])]
    ranked = alive.sort_values("abs_cohens_d", ascending=False)

    print(f"\n\nSeparation between benign and malicious npm packages")
    print("(Cohen's d: |d| > 0.8 large, 0.2-0.8 moderate, < 0.2 negligible)\n")
    print(f"  {'feature':<24} {'benign':>10} {'malicious':>11} {'d':>8}   strength")
    print("  " + "-" * 68)
    for _, r in ranked.iterrows():
        if abs(r["cohens_d"]) >= D_LARGE:
            strength = "LARGE"
        elif abs(r["cohens_d"]) >= D_SMALL:
            strength = "moderate"
        else:
            strength = "negligible"
        print(f"  {r['feature']:<24} {r['npm_benign_mean']:>10.1f} "
              f"{r['npm_malicious_mean']:>11.1f} {r['cohens_d']:>8.2f}   {strength}")


def report_cross_domain(diag):
    print("\n" + "=" * 78)
    print("PART 2: CROSS-DOMAIN COMPARABILITY")
    print("=" * 78)

    counts = diag["verdict"].value_counts()
    print("\nVerdict summary:")
    for verdict, n in counts.items():
        print(f"  {verdict:<16} {n}")

    mismatched = diag[diag["verdict"] == "SCALE_MISMATCH"].sort_values(
        "scale_ratio", ascending=False)
    if len(mismatched):
        print(f"\n\nScale mismatches (median differs by more than {SCALE_MISMATCH_FACTOR:.0f}x).")
        print("Same column name, different physical meaning.\n")
        print(f"  {'feature':<24} {'npm median':>12} {'qut median':>12} {'ratio':>10}")
        print("  " + "-" * 62)
        for _, r in mismatched.iterrows():
            ratio = "inf" if np.isinf(r["scale_ratio"]) else f"{r['scale_ratio']:.0f}x"
            print(f"  {r['feature']:<24} {r['npm_median']:>12.1f} "
                  f"{r['qut_median']:>12.1f} {ratio:>10}")

    dead_qut = diag[diag["verdict"] == "DEAD_QUT"]
    if len(dead_qut):
        print("\n\nDead in QUT but alive in npm.")
        print("The model was trained to ignore these, so npm signal here is wasted.\n")
        for _, r in dead_qut.iterrows():
            print(f"  {r['feature']:<24} npm range {r['npm_min']:.0f}-{r['npm_max']:.0f}, "
                  f"qut constant at {r['qut_min']:.0f}")


def report_scaler_damage(npm_df, qut_df, features, diag):
    """Show the constant z-score every npm sample inherits from a dead feature.

    This is the suspected mechanism behind the scrambled ranking: all 22 npm
    samples land on identical coordinates in these dimensions.
    """
    print("\n" + "=" * 78)
    print("PART 3: WHAT QUT-FITTED SCALING DOES TO DEAD FEATURES")
    print("=" * 78)

    X_qut = prepare_features(qut_df, features)
    X_npm = prepare_features(npm_df, features)

    scaler = StandardScaler().fit(X_qut)
    X_npm_scaled = scaler.transform(X_npm)

    dead_names = set(diag[diag["verdict"] == "DEAD_NPM"]["feature"])
    if not dead_names:
        print("\nNo npm-dead features to report.")
        return

    print("\nEvery npm sample receives an identical value in these dimensions,")
    print("regardless of whether the package is benign or malicious:\n")
    print(f"  {'feature':<24} {'z-score':>10}   spread across npm samples")
    print("  " + "-" * 66)

    total_offset = 0.0
    for i, feat in enumerate(features):
        if feat not in dead_names:
            continue
        col = X_npm_scaled[:, i]
        z, spread = col[0], col.std()
        total_offset += abs(z)
        print(f"  {feat:<24} {z:>10.3f}   {spread:.6f}")

    n_dead = len(dead_names)
    print(f"\n  {n_dead} of {len(features)} dimensions are frozen this way.")
    print(f"  Summed absolute displacement: {total_offset:.2f}")
    print("\n  Because the displacement is identical for every npm sample, these")
    print("  dimensions carry no information to separate benign from malicious,")
    print("  but they do push all npm samples into a region of feature space the")
    print("  trees only ever saw in QUT outliers.")


def report_direction_agreement(diag):
    """Compare which class runs higher in each domain.

    A CONFLICT feature is worse than a useless one: the QUT model learned a
    rule that fires in exactly the wrong direction on npm.
    """
    print("\n" + "=" * 78)
    print("PART 4: DOES EACH FEATURE POINT THE SAME WAY IN BOTH DOMAINS?")
    print("=" * 78)

    print("\nPositive d means malicious scores higher than benign.\n")
    print(f"  {'feature':<24} {'d (npm)':>9} {'d (qut)':>9}   direction")
    print("  " + "-" * 60)

    ordered = diag.sort_values("abs_cohens_d", ascending=False)
    for _, r in ordered.iterrows():
        print(f"  {r['feature']:<24} {r['cohens_d']:>9.2f} "
              f"{r['cohens_d_qut']:>9.2f}   {r['direction']}")

    conflicts = diag[diag["direction"] == "CONFLICT"]
    agrees = diag[diag["direction"] == "AGREE"]

    print(f"\n  AGREE: {len(agrees)}   CONFLICT: {len(conflicts)}   "
          f"weak in one or both: {len(diag) - len(agrees) - len(conflicts)}")

    if len(conflicts):
        print("\n  Features pointing opposite ways across domains:")
        for _, r in conflicts.sort_values("abs_cohens_d", ascending=False).iterrows():
            higher_npm = "malicious" if r["cohens_d"] > 0 else "benign"
            higher_qut = "malicious" if r["cohens_d_qut"] > 0 else "benign"
            print(f"    {r['feature']:<24} higher in {higher_qut} (qut) "
                  f"but {higher_npm} (npm)")

    if len(agrees) == 0:
        print("\n  No feature agrees across domains with a usable effect size.")
        print("  This alone is sufficient to explain a below-chance ranking.")


def report_whitelist(diag):
    print("\n" + "=" * 78)
    print("PART 5: RECOMMENDED FEATURE WHITELIST")
    print("=" * 78)

    comparable = diag["verdict"] == "TRANSFERABLE"
    discriminative_here = diag["abs_cohens_d"] >= D_SMALL
    discriminative_there = diag["abs_cohens_d_qut"] >= D_SMALL
    same_direction = diag["direction"] == "AGREE"

    keep = diag[comparable & discriminative_here & discriminative_there
                & same_direction].sort_values("abs_cohens_d", ascending=False)

    print("\nA feature is kept only if it clears all four bars:")
    print("  1. scales are comparable across domains")
    print("  2. separates classes in npm")
    print("  3. separates classes in QUT")
    print("  4. points the same direction in both")

    print(f"\n  passed 1 (comparable scale):        {comparable.sum():>2}")
    print(f"  passed 1+2 (also npm-discriminative): {(comparable & discriminative_here).sum():>2}")
    print(f"  passed 1+2+3 (also QUT-discriminative): "
          f"{(comparable & discriminative_here & discriminative_there).sum():>2}")
    print(f"  passed all 4 (also same direction):  {len(keep):>2}")

    if len(keep) == 0:
        print("\nNothing survives all four filters.")
        print("The transfer cannot be repaired by feature selection alone; the")
        print("two monitors are not measuring the same quantities.")
        return

    print(f"\nTRANSFERABLE_FEATURES = [")
    for _, r in keep.iterrows():
        print(f"    {r['feature']!r},  # d_npm={r['cohens_d']:+.2f} "
              f"d_qut={r['cohens_d_qut']:+.2f}")
    print("]")


def main():
    npm_df = load_npm()
    qut_df = load_qut_dataset()
    features = get_common_features()

    print(f"\nnpm sessions: {len(npm_df)} "
          f"({sum(npm_df['label_numeric'] == 0)} benign, "
          f"{sum(npm_df['label_numeric'] == 1)} malicious)")
    print(f"QUT samples:  {len(qut_df)}")
    print(f"Features:     {len(features)}")

    diag = build_diagnostics(npm_df, qut_df, features)

    report_npm_health(diag)
    report_cross_domain(diag)
    report_scaler_damage(npm_df, qut_df, features, diag)
    report_direction_agreement(diag)
    report_whitelist(diag)

    OUTPUT_DIR.mkdir(exist_ok=True)
    out_path = OUTPUT_DIR / "feature_diagnostics.csv"
    diag.to_csv(out_path, index=False)
    print(f"\n\nPer-feature table written to {out_path}")

    print("\nCaveat: 6 malicious npm samples is far too few for these effect")
    print("sizes to be conclusive. Treat the ranking as a map of where to look.")


if __name__ == "__main__":
    main()
