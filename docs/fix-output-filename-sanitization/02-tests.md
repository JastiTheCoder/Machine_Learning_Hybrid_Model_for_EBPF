# 2. Tests

Two tests were added, both in `internal/output/json_writer_test.go`, both using
the standard Go testing library with table-driven subtests. Both exercise the
public seam `JSONWriter.Write(SessionRecord) (string, error)`.

---

## Test 1 — `TestJSONWriterWritesInsideOutputDirForAwkwardPackageNames`

**The TDD slice.** Red before green.

Nine subtests, one per package spec form:

| Subtest | `PackageName` | What it represents |
|---|---|---|
| `relative_path_spec` | `./localdep` | the case actually hit in the previous task |
| `parent_path_spec` | `../escapee` | escapes the output directory |
| `nested_path_spec` | `./a/b/c` | multiple separators |
| `scoped_package` | `@scope/pkg` | ordinary registry usage, not exotic |
| `file_url_spec` | `file:../thing` | `:` plus traversal |
| `git_url_spec` | `git+https://example.com/x.git` | `+`, `:`, `//` |
| `bare_parent` | `..` | no separator, but a reserved name |
| `empty` | `""` | degenerate input |
| `overlong` | `"verylongname"×40` (480 chars) | exceeds the 255-byte filename limit |

Each subtest asserts four things:

```go
path, err := writer.Write(record)
if err != nil { t.Fatalf(...) }                         // goal 1: the write succeeds
if filepath.Dir(path) != outputDir { t.Errorf(...) }    // goal 2: it lands inside outputDir
...
if readBack.PackageName != tt.packageName { t.Errorf(...) }  // goal 3: data unchanged
if readBack.SessionID != record.SessionID { t.Errorf(...) }
```

The file is read back off disk and unmarshalled, so the assertions are made
against what was actually persisted rather than against what was passed in.

**Result: achieved.** 7 of 9 subtests failed before the change; all 9 pass after.

The two that passed before the change are worth naming honestly, because a
reader comparing the red and green logs will notice them:

- `bare_parent` (`..`) — produces `npm-1787403056_...json`, which is an ordinary
  legal filename. There is no separator, so no traversal.
- `empty` — produces `npm-1787403056_.json`. Also legal.

Neither was broken by the original code, so neither drove the change. They were
kept because they pin behaviour the sanitiser could plausibly have got wrong
(returning `""`, or a name starting with `.`).

Raw output: [`evidence/red-awkward-names.txt`](evidence/red-awkward-names.txt),
[`evidence/green-output-suite.txt`](evidence/green-output-suite.txt).

---

## Test 2 — `TestJSONWriterKeepsOrdinaryPackageNamesInFilename`

**A regression guard, not a TDD slice.** It passes both before and after the
change, and the comment in the source says so.

Seven subtests, one per package name the project actually captures:

```
lodash
benign-test-1.0.0.tgz
suspicious-test-1.0.0.tgz
ci-secret-grabber-test-1.0.0.tgz
crypto-miner-test-1.0.0.tgz
env-stealer-test-1.0.0.tgz
reverse-shell-test-1.0.0.tgz
```

Each asserts the exact filename, against an independently written literal:

```go
want := "npm-1787403056_" + name + ".json"
if got := filepath.Base(path); got != want { t.Errorf(...) }
```

This exists because sanitisation is a change to an output format that something
downstream depends on. Per the **C4** finding in `AUDIT.md`, the dataset labeller
assigns ground-truth labels by matching substrings of the filename — `suspicious`,
`crypto-miner`, and so on. A sanitiser that rewrote those names would silently
relabel the training data, which is a far worse bug than the one being fixed.

**Result: achieved.** All 7 pass, unchanged, before and after.

---

## Test 3 — end-to-end against the real binary

Not a Go test; a manual run, because the thing being proved is that the shipped
binary writes a file, and the previous failure was observed in exactly that way.

1. Built `cmd/monitor` and started it as root against a scratch output directory.
2. Created a package with a local path dependency.
3. Ran `npm install ./localdep --no-audit --no-fund`.
4. Read the output directory, and the directory above it.

**Result: achieved.**

```
2026/08/22 18:45:08 wrote session record: .../e2e/out/npm-1787404508_localdep.json
```

```
  "session_id": "npm-1787404508",
  "package_name": "./localdep",
```

The file exists, is named safely, sits inside the output directory, nothing was
written above it, and the record still reports the spec verbatim — goals 1, 2, 3
and 5 confirmed simultaneously against the real thing.

Raw output: [`evidence/e2e-monitor-session.txt`](evidence/e2e-monitor-session.txt),
[`evidence/e2e-session-localdep.json`](evidence/e2e-session-localdep.json).

---

## Goal coverage

| Goal | Covered by | Achieved |
|---|---|---|
| 1 — no session lost to its package name | Test 1 (`err == nil`), Test 3 | yes |
| 2 — file lands inside the output directory | Test 1 (`filepath.Dir`), Test 3 | yes |
| 3 — recorded data unchanged | Test 1 (round-trip `package_name`), Test 3 | yes |
| 4 — existing filenames unchanged | Test 2 | yes |
| 5 — proven against the real binary | Test 3 | yes |
