"""
Investigate why malicious patterns don't match
"""
import pandas as pd
import numpy as np
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
QUT_REF = SCRIPT_DIR / "qut-reference-196.csv"
CORPUS_17 = SCRIPT_DIR / "corpus-17-schema2.csv"

FEATURES = ['p1_count', 'p2_count', 'p3_count', 'p4_count', 'p5_count']

# Load data
qut = pd.read_csv(QUT_REF, encoding='utf-8-sig')
corpus = pd.read_csv(CORPUS_17, encoding='utf-8-sig')

print("=" * 70)
print("QUT MALICIOUS vs BENIGN (Pattern Features)")
print("=" * 70)

qut_ben = qut[qut['label'] == 0][FEATURES]
qut_mal = qut[qut['label'] == 1][FEATURES]

print(f"\n{'Feature':<15} {'Benign Mean':>12} {'Malicious Mean':>15} {'Difference':>12}")
print("-" * 55)
for feat in FEATURES:
    ben_mean = qut_ben[feat].mean()
    mal_mean = qut_mal[feat].mean()
    diff = mal_mean - ben_mean
    print(f"{feat:<15} {ben_mean:>12.1f} {mal_mean:>15.1f} {diff:>+12.1f}")

print("\n" + "=" * 70)
print("QUT MALICIOUS n-grams (most common)")
print("=" * 70)

qut_mal_full = qut[qut['label'] == 1]
print("\nMost common p1_ngram in QUT malicious:")
print(qut_mal_full['p1_ngram'].value_counts().head(10))

print("\n" + "=" * 70)
print("OUR MALICIOUS CAPTURES")
print("=" * 70)

our_mal = corpus[corpus['label'] == 1]
print(f"\n{'Package':<35} {'p1_ngram':<45} {'p1_count':>10}")
print("-" * 95)
for _, row in our_mal.iterrows():
    print(f"{row['package_name']:<35} {row['p1_ngram']:<45} {row['p1_count']:>10}")

print("\n" + "=" * 70)
print("OUR BENIGN CAPTURES")
print("=" * 70)

our_ben = corpus[corpus['label'] == 0]
print(f"\n{'Package':<35} {'p1_ngram':<45} {'p1_count':>10}")
print("-" * 95)
for _, row in our_ben.iterrows():
    print(f"{row['package_name']:<35} {row['p1_ngram']:<45} {row['p1_count']:>10}")

print("\n" + "=" * 70)
print("PATTERN COMPARISON: QUT vs OURS")
print("=" * 70)

print(f"\n{'Metric':<25} {'QUT Benign':>12} {'QUT Malicious':>14} {'Our Benign':>12} {'Our Malicious':>14}")
print("-" * 80)

our_ben_vals = corpus[corpus['label'] == 0][FEATURES]
our_mal_vals = corpus[corpus['label'] == 1][FEATURES]

for feat in FEATURES:
    qb = qut_ben[feat].mean()
    qm = qut_mal[feat].mean()
    ob = our_ben_vals[feat].mean()
    om = our_mal_vals[feat].mean()
    print(f"{feat:<25} {qb:>12.1f} {qm:>14.1f} {ob:>12.1f} {om:>14.1f}")

print("\n" + "=" * 70)
print("KEY INSIGHT")
print("=" * 70)
print("""
In QUT-DV25, malicious packages are distinguished by their pattern features.
Let's see if there's a clear difference in the QUT data that our malicious
packages don't exhibit.
""")

# Check if QUT malicious have different patterns
print("\nQUT pattern distribution:")
print(f"  Benign p1_count:    median={qut_ben['p1_count'].median():.0f}, IQR=[{qut_ben['p1_count'].quantile(0.25):.0f}, {qut_ben['p1_count'].quantile(0.75):.0f}]")
print(f"  Malicious p1_count: median={qut_mal['p1_count'].median():.0f}, IQR=[{qut_mal['p1_count'].quantile(0.25):.0f}, {qut_mal['p1_count'].quantile(0.75):.0f}]")

print("\nOur pattern distribution:")
print(f"  Benign p1_count:    median={our_ben_vals['p1_count'].median():.0f}")
print(f"  Malicious p1_count: median={our_mal_vals['p1_count'].median():.0f}")
