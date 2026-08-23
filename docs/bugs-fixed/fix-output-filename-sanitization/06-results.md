# 6. Results

## Goals vs. outcome

| # | Goal | Outcome |
|---|---|---|
| 1 | No session lost because of its package name | **met** — all 9 awkward specs write successfully; the real `npm install ./localdep` now produces a file |
| 2 | File always inside the output directory | **met** — `filepath.Dir(path) == outputDir` asserted for all 9; nothing written above `<out>` in the real run |
| 3 | Recorded data unchanged | **met** — `package_name` round-trips verbatim in every case, including `"./localdep"` in the real session |
| 4 | Existing filenames unchanged | **met** — all 7 corpus names byte-for-byte identical |
| 5 | Proven against the real binary | **met** — `wrote session record: .../npm-1787404508_localdep.json` |

## The measurement that matters

The same command, before and after.

**Before** (observed during the previous task, `docs/fix-processtracer-fork-load/`):

```
write session npm-1787403056: open <out>/npm-1787403056_./localdep.json: no such file or directory
```

Session discarded. Exit status of the monitor: unaffected. Files in the output
directory: zero.

**After:**

```
2026/08/22 18:45:08 wrote session record: /home/ani/.claude/jobs/d9878835/tmp/e2e/out/npm-1787404508_localdep.json
```

```
-rw-r--r-- 1 root root 1275 Aug 22 18:45 npm-1787404508_localdep.json
```

```json
  "session_id": "npm-1787404508",
  "package_name": "./localdep",
```

The filename is safe, the file is inside the output directory, and the record
still reports the spec exactly as npm received it.

## Test results

`internal/output`, full package, after the change:

```
--- PASS: TestJSONWriter_WriteSuccess
--- PASS: TestSessionRecord_ToCSVRow_LegacyUserlibAlias
--- PASS: TestBuildRecord_NilSafety
--- PASS: TestValidate
--- PASS: TestJSONWriterWritesInsideOutputDirForAwkwardPackageNames
    --- PASS: .../relative_path_spec
    --- PASS: .../parent_path_spec
    --- PASS: .../nested_path_spec
    --- PASS: .../scoped_package
    --- PASS: .../file_url_spec
    --- PASS: .../git_url_spec
    --- PASS: .../bare_parent
    --- PASS: .../empty
    --- PASS: .../overlong
--- PASS: TestJSONWriterKeepsOrdinaryPackageNamesInFilename
    --- PASS: .../lodash
    --- PASS: .../benign-test-1.0.0.tgz
    --- PASS: .../suspicious-test-1.0.0.tgz
    --- PASS: .../ci-secret-grabber-test-1.0.0.tgz
    --- PASS: .../crypto-miner-test-1.0.0.tgz
    --- PASS: .../env-stealer-test-1.0.0.tgz
    --- PASS: .../reverse-shell-test-1.0.0.tgz
--- PASS: TestValidateRecord_AllPresent
--- PASS: TestValidateRecord_MissingField
--- PASS: TestValidateRecord_ZeroValue
PASS
ok  	github.com/aniruddha/npm-ebpf-monitor/internal/output	0.005s
```

Red → green on the slice: **7 of 9 subtests failing → 0 failing**.

## Whole-repository verification

```
$ go build ./...
BUILD OK

$ go test -race ./... -count=1
ok  	.../cmd/monitor          1.014s
ok  	.../internal/collector   1.011s
ok  	.../internal/features    1.012s
ok  	.../internal/output      1.030s
ok  	.../internal/session     1.227s

$ sudo -n /usr/bin/go test ./... -count=1
ok  	.../cmd/monitor          0.003s
ok  	.../internal/collector   1.075s
ok  	.../internal/features    2.207s
ok  	.../internal/output      0.010s
ok  	.../internal/session     0.213s
```

Both suites fully green, including the root-only eBPF tests added by the two
previous fixes. `gofmt` clean on both changed files; `go vet ./internal/output/`
clean.

## Diff size

| File | Change |
|---|---|
| `internal/output/json_writer.go` | +1 import, +2 lines at the write site, +43 lines of sanitiser and comments |
| `internal/output/json_writer_test.go` | +1 import, +2 tests |

No BPF source touched, no object regenerated, no generated Go changed.

## What this unblocks

Re-capturing the session corpus. That was the step this fix was a prerequisite
for: with the ProcessTracer load failure fixed the monitor runs, and with this
fixed a capture run over local `.tgz` fixtures will not silently drop sessions
whose spec contains a path separator — which, for the malicious fixtures, is all
of them.
