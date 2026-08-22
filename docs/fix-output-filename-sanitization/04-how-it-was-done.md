# 4. How it was done, step by step

The `tdd` skill's loop: confirm the seam, write one failing test, watch it fail
for the right reason, make it pass, then verify nothing else moved.

## Step 1 — locate the defect precisely

Read `internal/output/json_writer.go` and found the interpolation at line 173.
Read `cmd/monitor/main.go` to confirm *why* the failure was silent rather than
loud, and found the `log.Printf` / `continue` pair at lines 290-295. Both facts
were needed: the first is the bug, the second is what makes it dangerous.

## Step 2 — choose the seam

`JSONWriter.Write(record SessionRecord) (string, error)` — public, pure Go, no
kernel, no root, runs in microseconds.

This is a deliberate contrast with the two previous fixes. Those both had to be
tested against a live kernel, because the defect lived in the BPF producer and
any userspace test would have been testing a hand-built struct rather than the
thing that was broken. Here the defect is entirely in a Go function that takes a
struct and writes a file, so the honest seam is the Go function. Reaching for
the kernel would have been ceremony, not rigour.

The seam is also *exactly* where the bug is observable: `Write` returns the path,
so a test can assert both the error and the location without touching internals.

## Step 3 — write the failing test

Wrote `TestJSONWriterWritesInsideOutputDirForAwkwardPackageNames` as a
table-driven test over nine specs, asserting four properties per case.

A note on what the test asserts, because there was a real choice here. The
obvious test would have pinned the exact sanitised filename for each awkward
input:

```go
{packageName: "./localdep", wantFile: "npm-1787403056_localdep.json"},
```

That was rejected. It couples the test to one particular sanitisation scheme —
change `-` to `_` and every case breaks, despite the behaviour that anyone
actually cares about being unchanged. What the project needs from these inputs
is *properties*: the write succeeds, the file is inside the output directory,
the data survives. So those are what the test asserts.

The exact-filename assertion is used in the second test, where pinning the
literal *is* the requirement, because backward compatibility means precisely
"this exact string".

## Step 4 — run it red

```
$ go test ./internal/output/ -run TestJSONWriterWritesInsideOutputDirForAwkwardPackageNames -count=1 -v
```

Seven of nine failed, and — the part that matters — each failed with the message
predicted in the audit, naming the malformed path:

```
Write(package="./localdep") = open <tmp>/npm-1787403056_./localdep.json: no such file or directory, want nil
Write(package="../escapee") = open <tmp>/npm-1787403056_../escapee.json: no such file or directory, want nil
Write(package="@scope/pkg") = open <tmp>/npm-1787403056_@scope/pkg.json: no such file or directory, want nil
```

The `overlong` case failed differently — `ENAMETOOLONG` rather than `ENOENT` —
which is what drove `maxFilenamePart` into the design. The `bare_parent` and
`empty` cases passed, as recorded in [02-tests.md](02-tests.md).

Red for the right reason, confirmed per case, not just "the suite is red".

Raw: [`evidence/red-awkward-names.txt`](evidence/red-awkward-names.txt).

## Step 5 — write the backward-compatibility guard first

Before implementing, added `TestJSONWriterKeepsOrdinaryPackageNamesInFilename`
and confirmed it passed *against the unmodified code*. Order matters: a guard
written after the change proves nothing, because it can only ever encode what
the new code already does. Written before, it encodes the old behaviour and can
genuinely catch a regression.

It duly passed on the original implementation — visible in the same run as the
red slice.

## Step 6 — implement

Added `sanitizeFilenamePart` and wired it into `Write`, as described in
[03-what-was-done.md](03-what-was-done.md).

## Step 7 — run it green

```
$ go test ./internal/output/ -count=1 -v
ok  	github.com/aniruddha/npm-ebpf-monitor/internal/output	0.005s
```

All nine awkward-name subtests pass, all seven guard subtests pass, and the four
pre-existing tests in the package (`TestJSONWriter_WriteSuccess`,
`TestSessionRecord_ToCSVRow_LegacyUserlibAlias`, `TestBuildRecord_NilSafety`,
`TestValidate`, plus the three `TestValidateRecord_*`) still pass untouched.

Raw: [`evidence/green-output-suite.txt`](evidence/green-output-suite.txt).

## Step 8 — record the actual mapping

A property test proves the properties hold but does not show what the filenames
*look like*, and someone reviewing a change to an output format should be able
to see that. Wrote a throwaway test that dumped every input/output pair, ran it,
saved the result to
[`evidence/sanitizer-mapping.txt`](evidence/sanitizer-mapping.txt), and deleted
the throwaway. It is documentation, not a test, so it is not left in the suite.

Reading it back is what surfaced the `file:../thing` → `file-..-thing` case,
which is written up explicitly rather than left for a reviewer to trip over.

## Step 9 — verify the whole repository

```
$ go build ./...                     BUILD OK
$ go test -race ./... -count=1       all ok
$ sudo -n /usr/bin/go test ./... -count=1   all ok
```

The race suite matters because the writer runs on the monitor's session-completion
goroutine. Raw: [`evidence/race-suite.txt`](evidence/race-suite.txt),
[`evidence/root-suite.txt`](evidence/root-suite.txt).

## Step 10 — end-to-end against the real binary

The unit tests prove the function is correct. They do not prove the *monitor*
now keeps the session, because that path also runs through session tracking,
feature aggregation, and the error-swallowing call site. Since the original
failure was observed in a real run, the fix was confirmed in a real run.

```
$ sudo -n /usr/bin/go run ./cmd/monitor -output-dir <out> -verbose -session-timeout 60s &
$ cd <proj> && npm install ./localdep --no-audit --no-fund
added 1 package in 184ms
```

```
$ ls -la <out>
-rw-r--r-- 1 root root 1275 Aug 22 18:45 npm-1787404508_localdep.json
```

Also checked the directory *above* the output directory, to confirm nothing had
escaped. Nothing had.

Raw: [`evidence/e2e-monitor-session.txt`](evidence/e2e-monitor-session.txt),
[`evidence/e2e-session-localdep.json`](evidence/e2e-session-localdep.json).
