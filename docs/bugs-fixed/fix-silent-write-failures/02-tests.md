# 2. Tests

Two tests were added to `cmd/monitor/main_test.go`, both table-driven with
subtests, both using the standard Go testing library.

---

## Test 1 — `TestRunOutputWorkerReportsWriteOutcomes`

The main slice. Drives the real `runOutputWorker` with a real `JSONWriter` over
a real filesystem, and asserts the counts it returns.

| Subtest | Sessions | Writer | Want written | Want failed |
|---|---|---|---|---|
| `all writes succeed` | 3 | `t.TempDir()` | 3 | 0 |
| `all writes fail` | 3 | failing writer | 0 | 3 |
| `no sessions at all` | 0 | `t.TempDir()` | 0 | 0 |

The `all writes fail` case carries goal 4 as well as goal 1: asserting
`failed == 3` rather than `failed >= 1` proves the worker attempted **every**
session in the batch rather than stopping at the first error. A worker that
aborted on failure would report `1` and fail this test.

### Forcing a write failure deterministically

This needed care, and the obvious approach would have produced a test that
silently stopped testing anything.

```go
func newFailingWriter(t *testing.T) *output.JSONWriter {
	t.Helper()

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("create blocker file: %v", err)
	}

	return output.NewJSONWriter(filepath.Join(blocker, "sessions"))
}
```

The output directory's *parent* is a regular file, so `Write`'s opening
`os.MkdirAll` fails with `ENOTDIR`.

The natural alternative — a directory with mode `0o555` — was rejected because
**root bypasses permission checks**, and this repository's suite is run under
`sudo` so the eBPF tests can load. A permissions-based failing writer would
therefore pass under `go test` and quietly stop failing under
`sudo -n /usr/bin/go test`, leaving a test that asserts `failed == 3` against a
writer that succeeds — it would go red, but for a reason no one would connect to
root. `ENOTDIR` is a structural failure that root cannot bypass.

This was verified rather than assumed:

```
$ sudo -n /usr/bin/go test ./cmd/monitor/ -run TestRunOutputWorkerReportsWriteOutcomes -count=1 -v
    --- PASS: TestRunOutputWorkerReportsWriteOutcomes/all_writes_succeed
    --- PASS: TestRunOutputWorkerReportsWriteOutcomes/all_writes_fail
    --- PASS: TestRunOutputWorkerReportsWriteOutcomes/no_sessions_at_all
```

**Result: achieved.** Red as a compile failure (the function returned nothing),
green on all three subtests, as non-root and as root.

---

## Test 2 — `TestExitCodeForOutputFailsWhenSessionsWereLost`

Pins the exit-status decision.

| Subtest | `outputStats` | Want |
|---|---|---|
| `nothing written, nothing failed` | `{}` | 0 |
| `everything written` | `{written: 12}` | 0 |
| `one session lost` | `{written: 11, failed: 1}` | 1 |
| `everything lost` | `{failed: 12}` | 1 |

The `one session lost` case is the one that matters: a run that mostly worked
must still fail. An 11-of-12 corpus that exits zero is precisely the outcome
this whole change exists to prevent.

`nothing written, nothing failed` pins the other easy mistake — treating "no
sessions" as an error. Starting the monitor and stopping it without running an
install is not a failure.

**Result: achieved.** All 4 subtests pass.

---

## What was *not* tested, and why it is stated here rather than buried

The full process exit status was **not** verified end to end. Doing so requires
starting the monitor (root, for BPF) and sending it `SIGINT`; the sudo grant in
this environment covers only the `go` binary, so a root-owned monitor process
cannot be signalled from here.

What is verified instead: the decision function is unit-tested above, and the
wiring that calls it is recorded verbatim in
[`evidence/wiring.txt`](evidence/wiring.txt). The gap between those two and a
real signalled shutdown is small but real, and the command to close it is given
in [07-findings-not-fixed.md](07-findings-not-fixed.md).

---

## Goal coverage

| Goal | Covered by | Achieved |
|---|---|---|
| 1 — count written and lost | Test 1 | yes |
| 2 — report at shutdown | inspection + `evidence/wiring.txt` | wired, not exercised end to end |
| 3 — exit non-zero on loss | Test 2 | yes (decision); wiring not exercised |
| 4 — do not abort the run | Test 1, `failed == 3` | yes |
| 5 — change nothing else | full suite, `-race` and root | yes |
