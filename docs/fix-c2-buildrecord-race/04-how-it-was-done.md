# 4. How it was done — four slices

## Step 0 — verify the audit's claims rather than trust them

Read `BuildRecord`, then every mutator in `session.go`, then grepped the
`features` package for mutexes:

```
=== which aggregator types carry their own mutex? ===
MUTEX in filetop_aggregator.go: 1 refs
```

Confirmed: `FiletopAggregator` has `mu sync.Mutex`; `DirCounts`,
`TCPAggregator` and `NGramCounter` do not — and `TCPAggregator` holds four maps.
Then read `RouteToSession` and confirmed it releases `d.mu` *before* calling
`fn(session)`, which is what makes the race reachable.

Also ran the existing `TestConcurrency` and read it: 100 goroutines, **all
writers**. Writers mutually exclude via `s.mu`, so it can pass forever with C2
present.

## Step 0b — confirm seams and the fix approach with the user

Four seams and three candidate fixes were put to the user before any test was
written. Chosen: `Session.Snapshot()`. All four seams confirmed.

## Slice 1 — `Snapshot()` returns an independent, correct view

**Red:** `session.Snapshot undefined (type *Session has no field or method Snapshot)`

**Green:** implemented `Snapshot` with the lock. The lock is not "anticipating a
future test" here — it is the entire reason the method exists, and writing it
unlocked would have been contrived.

Raw: [`slice1-red.txt`](evidence/slice1-red.txt), [`slice1-green.txt`](evidence/slice1-green.txt).

## Slice 2 — `BuildRecord` under concurrent writers

**Red**, under `-race`, against `BuildRecord` still reading fields directly:

```
DATA RACE reports: 10
    testing.go:1712: race detected during execution of test
FAIL
```

A filtering mistake is worth recording here: the first capture used
`grep -vE 'WARN'` to strip slog noise, which also swallowed every
`WARNING: DATA RACE` header and made the report read as 0 races. Caught by the
count disagreeing with the visible stack traces, and re-captured with
`grep -vE 'WARN session record'`. The evidence file is the corrected run.

**Green:** rewired `BuildRecord` onto `sess.Snapshot()`, renamed
`sessionTimestamp` → `snapshotTimestamp`. 10 races → 0.

Raw: [`slice2-red.txt`](evidence/slice2-red.txt), [`slice2-green.txt`](evidence/slice2-green.txt).

## Slice 3 — the end-to-end seam, and the negative result

Built the production-faithful test: a real `Detector`, driven through its
exported API, with collector events still flowing as the session completes.

It passed. **A guard that passes proves nothing until you know it can fail**, so
the fix was temporarily reverted — `BuildRecord` restored to direct field reads
— and the test re-run:

```
=== slice 3 against the REVERTED (buggy) BuildRecord ===
DATA RACE reports: 0
ok  ...internal/output  1.008s
```

No teeth. The cause is structural: `unregisterSession` removes the session's
PIDs from `d.pidToSession` on completion, so `RouteToSession` immediately stops
finding it and the writers fall silent. The real window is a few instructions
wide inside `RouteToSession` and is not reachable from outside the package.

The fix was restored, the test relabelled with the negative result in its own
doc comment, and slice 2 stands as the C2 regression test.

Raw: [`slice3-teeth-check.txt`](evidence/slice3-teeth-check.txt).

## Slice 4 — pin the new boundary's concurrency guarantee

`TestSnapshotIsRaceFreeUnderConcurrentWriters`: six writers against a reader
calling `Snapshot()` and reading the cloned map, under `-race`. Passes
immediately — labelled a guard in both the source and [02-tests.md](02-tests.md).

Raw: [`slice4-green.txt`](evidence/slice4-green.txt).

## Step 5 — verify the repository

```
$ gofmt -l internal/session/ internal/output/   (only pre-existing offenders)
$ go build ./...                                BUILD OK
$ go vet ./...                                  clean
$ go test -race ./... -count=1                  all ok (9 packages)
$ sudo -n /usr/bin/go test ./... -count=1       all ok (9 packages)
```

Raw: [`race-suite.txt`](evidence/race-suite.txt), [`root-suite.txt`](evidence/root-suite.txt).
