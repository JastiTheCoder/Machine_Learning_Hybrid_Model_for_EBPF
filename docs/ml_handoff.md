# ML Handoff — Session CSV Export

This document explains how to export the collected npm-ebpf-monitor sessions into
a CSV ready for model training, and the exact column layout the ML team should
expect.

> **Schema 1.2.0 changed this export.** The CSV was 39 columns and matched
> QUT-DV25's 36-feature schema. QUT-DV25 has been retired as a training source
> (see [`ml_analysis/QUT_RETIREMENT.md`](../ml_analysis/QUT_RETIREMENT.md)), so
> the export is no longer constrained by it. Two things changed:
>
> 1. **20 new `sensitive` columns** carry credential-path and event-ordering
>    signal the monitor already gathered but previously discarded. Total is now
>    59 columns.
> 2. **The `p1`-`p10` n-gram columns changed meaning.** They now count
>    gap-tolerant sequences rather than exactly-consecutive ones.
>
> Every pre-existing column keeps its position, so old and new CSVs can be
> compared on columns 1-38 and 59. They **cannot** be pooled on `p1`-`p10`.

---

## 1. Generate the CSV (Go)

The exporter is a standalone Go binary that reads every `.json` session file and
writes a 59-column CSV.

```bash
# From the project root:
go run ./cmd/dataset/exporter \
  --dir ./sessions/dataset/ \
  --out ./sessions/sessions.csv
```

Expected output:

```
Wrote 18 rows to ./sessions/sessions.csv.
```

Sessions with no label are refused, not defaulted to benign (AUDIT.md C4). If
any are skipped the exporter exits non-zero — run the labeler and export again.

---

## 2. Verify the CSV structure

```bash
# Check column count (expected: 59)
head -n 1 ./sessions/sessions.csv | awk -F, '{print "Columns: " NF}'

# Check label distribution
awk -F, 'NR>1 {print $2}' ./sessions/sessions.csv | sort | uniq -c
# Example expected output:
#   15 0   <- benign
#    3 1   <- malicious
```

The exporter fails loudly if a row's width does not match the header, so a
silently misaligned dataset is not a failure mode you need to check for by hand.

---

## 3. Column layout (59 columns)

### Metadata and legacy features (columns 1-38)

| # | Column name | Source |
|---|-------------|--------|
| 1 | `package_name` | Session metadata |
| 2 | `label` | 0 = benign, 1 = malicious |
| 3 | `read_processes` | filetop |
| 4 | `write_processes` | filetop |
| 5 | `read_data_transfer_kb` | filetop |
| 6 | `write_data_transfer_kb` | filetop |
| 7 | `file_access_processes` | filetop |
| 8 | `total_dependencies` | install |
| 9 | `direct_dependencies` | install |
| 10 | `indirect_dependencies` | install |
| 11 | `root_dir_access` | opensnoop |
| 12 | `temp_dir_access` | opensnoop |
| 13 | `home_dir_access` | opensnoop |
| 14 | `user_dir_access` | opensnoop |
| 15 | `sys_dir_access` | opensnoop |
| 16 | `etc_dir_access` | opensnoop |
| 17 | `other_dir_access` | opensnoop |
| 18 | `state_transitions` | tcp |
| 19 | `local_ips` | tcp |
| 20 | `remote_ips` | tcp |
| 21 | `local_ports` | tcp |
| 22 | `remote_ports` | tcp |
| 23 | `io_ops` | syscalls |
| 24 | `file_ops` | syscalls |
| 25 | `network_ops` | syscalls |
| 26 | `time_ops` | syscalls |
| 27 | `security_ops` | syscalls |
| 28 | `process_ops` | syscalls |
| 29 | `p1_file_metadata` | n-gram patterns |
| 30 | `p2_read_data` | n-gram patterns |
| 31 | `p3_write_data` | n-gram patterns |
| 32 | `p4_socket_create` | n-gram patterns |
| 33 | `p5_process_create` | n-gram patterns |
| 34 | `p6_memory_map` | n-gram patterns |
| 35 | `p7_fd_manage` | n-gram patterns |
| 36 | `p8_ipc` | n-gram patterns |
| 37 | `p9_file_lock` | n-gram patterns |
| 38 | `p10_error_handle` | n-gram patterns |

### Sensitive-access features (columns 39-58, new in 1.2.0)

All are `0`/`1` flags except `persistence_writes`, `distinct_endpoints` and
`non_root_endpoints`, which are counts.

| # | Column name | Meaning |
|---|-------------|---------|
| 39 | `ssh_private_key_read` | Read `~/.ssh/id_rsa`, `id_ed25519`, etc. |
| 40 | `aws_credentials_read` | Read `~/.aws/credentials` or `config` |
| 41 | `docker_config_read` | Read `~/.docker/config.json` |
| 42 | `kube_config_read` | Read `~/.kube/config` |
| 43 | `crypto_wallet_read` | Read `wallet.dat` or an Electrum directory |
| 44 | `dotenv_read` | Read a `.env` file |
| 45 | `npmrc_read` | Read `.npmrc` — **fires on nearly every install** |
| 46 | `gitconfig_read` | Read `.gitconfig` |
| 47 | `etc_passwd_read` | Read `/etc/passwd` |
| 48 | `etc_shadow_read` | Read `/etc/shadow` |
| 49 | `shellrc_read` | Read `.bashrc`, `.zshrc`, `.profile` |
| 50 | `crondir_read` | Read `/etc/crontab` or a `cron.d` entry |
| 51 | `systemd_unit_read` | Read a systemd unit file |
| 52 | `persistence_writes` | Count of distinct startup locations **written** |
| 53 | `credential_class_read` | Any of columns 39-42 |
| 54 | `distinct_endpoints` | Distinct `ip:port` connected to (capped at 32) |
| 55 | `non_root_endpoints` | Distinct endpoints from a non-npm-root PID |
| 56 | `credential_read_before_connect` | A credential read preceded an outbound connection |
| 57 | `sensitive_read_before_connect` | Any sensitive read preceded an outbound connection |
| 58 | `spawn_before_connect` | A process spawn preceded an outbound connection |

| # | Column name | Source |
|---|-------------|--------|
| 59 | `severity_score` | derived (mirrors label) |

Notes on the sensitive block:

- **`npmrc_read` is near-constant.** npm reads `.npmrc` during ordinary registry
  config resolution on every install, so expect it to be `1` almost everywhere
  and carry little signal. It is exported anyway because its *absence* is
  informative, and because keeping it visible is what stops it being quietly
  folded into `credential_class_read`, which is the mistake audit finding NC1
  documents.
- **Columns 56-58 are the ordering features.** Aggregate counts cannot
  distinguish read-then-send from send-then-read, and only the first is
  exfiltration. These are the only columns in the export that carry temporal
  information.
- **`unknown_ops`** is still present in the JSON and still excluded from the
  CSV; load it from the JSON directly if you want it.

---

## 4. Load the CSV in Python (pandas)

```python
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

df = pd.read_csv("sessions/sessions.csv")

print(f"Shape: {df.shape}")          # (N, 59)
print(df["label"].value_counts())    # 0: benign, 1: malicious

FEATURE_COLS = [c for c in df.columns
                if c not in ("package_name", "label", "severity_score")]

X = df[FEATURE_COLS]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

print(classification_report(y_test, clf.predict(X_test)))

importances = pd.Series(clf.feature_importances_, index=FEATURE_COLS)
print(importances.sort_values(ascending=False).head(10))
```

### Key decisions encoded in the CSV

| Decision | Detail |
|----------|--------|
| **Label encoding** | Binary: `0` = benign, `1` = malicious |
| **`severity_score`** | Mirrors `label` (baseline); drop it from features, it is a label leak |
| **`unknown_ops`** | Present in JSON but excluded from CSV export |
| **`.ssh` / `.aws` paths** | Still `other_dir_access` at the BPF layer, but now also surfaced per-class in columns 39-43 |
| **Data transfer** | Approximate KB values from filetop |
| **Verdict output** | Not exported as columns. It is derived from the same events, and `assign_label` in `ml_analysis/feature_analysis.py` derives labels from `verdict_level` — using it as a feature is circular until labels come from an external corpus |

### Two traps worth stating explicitly

**`severity_score` is a copy of the label.** Leaving it in `X` gives a model
100% accuracy that means nothing. The snippet above excludes it; keep it
excluded.

**The current corpus cannot support an honest accuracy number.** The benign
class is real libraries plus synthetic fixtures, and the malicious class is
entirely synthetic fixtures built from one template. Any feature that separates
"written from that template" from "real library" reads as a malware signal.
`os_user_dir` demonstrates this: it shows Cohen's d = 2.70 off a 3% difference,
because every benign session reads 865 or 879 and every malicious one reads
904-913. Results on this corpus are a pipeline smoke test, not an evaluation.

---

## 5. Re-running after adding more sessions

```bash
# 1. Label new sessions
go run ./cmd/dataset/labeler --dir ./sessions/dataset/

# 2. Re-export CSV
go run ./cmd/dataset/exporter \
  --dir ./sessions/dataset/ \
  --out ./sessions/sessions.csv

# 3. Validate
head -n 1 ./sessions/sessions.csv | awk -F, '{print "Columns: " NF}'
```

---

## 6. Mixing sessions captured before and after 1.2.0

Check `schema_version` in the session JSON before pooling.

| Columns | Safe to pool across 1.1.0 and 1.2.0? |
|---|---|
| 1-28, 59 | Yes, unchanged |
| 29-38 (`p1`-`p10`) | **No.** Counting rule changed from consecutive to gap-tolerant |
| 39-58 (sensitive) | Absent before 1.2.0. Reads as all-zero, which is indistinguishable from a genuinely clean session |

The clean approach is to re-capture rather than pool. If you must pool, drop
columns 29-58 for the combined run.
