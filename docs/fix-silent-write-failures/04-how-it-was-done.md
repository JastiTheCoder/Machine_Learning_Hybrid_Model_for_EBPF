# 4. How it was done, step by step

## Step 1 — find the seam

`grep -nE '^func ' cmd/monitor/main.go` gave eleven functions. The write happens
in `runOutputWorker` (line 277 before the change), called once from `main` at
line 148 inside a `startTrackedGoroutine` closure.

Reading it showed the seam was awkward for the wrong reason: the function took a
`*session.Detector` but used only `detector.Completed()`. Testing it as written
would have meant constructing a detector and feeding it synthetic process-exec
events just to get one session to the other side — a lot of machinery
exercising code the test has no interest in.

Narrowing the parameter to `<-chan *session.Session` was decided here, before
any test was written, as part of confirming the seam. It is not a refactor
smuggled into the change: it removes a dependency the function never used.

## Step 2 — decide how to make a write fail

The test needs `writer.Write` to fail on demand. Three candidates:

1. **A read-only output directory** (`0o555`). Rejected. This repository's suite
   is run under `sudo` so the eBPF tests can load, and root ignores directory
   permissions — the writer would succeed, the assertion `failed == 3` would go
   red, and the reason would be entirely non-obvious. A test that stops testing
   under the exact conditions the project actually runs it in is worse than no
   test.
2. **A mock writer.** Rejected: `runOutputWorker` takes a concrete
   `*output.JSONWriter`, so this would mean introducing an interface purely for
   the test, and the resulting test would no longer prove anything about the
   real writer's failure behaviour.
3. **A path whose parent is a regular file.** Chosen. `Write` begins with
   `os.MkdirAll(w.outputDir, 0o755)`, which fails with `ENOTDIR`. Structural,
   deterministic, and not something root can bypass.

The root assumption behind (3) was checked rather than trusted — see step 6.

## Step 3 — write the failing tests

Wrote both tests plus the two helpers. `feedSessions(n)` returns a pre-filled,
closed channel, so the worker's `range` terminates without any goroutine or
timeout in the test.

## Step 4 — run it red

```
$ go test ./cmd/monitor/ -count=1
cmd/monitor/main_test.go:165:13: runOutputWorker(...) (no value) used as value
cmd/monitor/main_test.go:165:29: cannot use feedSessions(tt.sessions) (value of type <-chan *session.Session) as *session.Detector value in argument to runOutputWorker
cmd/monitor/main_test.go:186:9: undefined: outputStats
cmd/monitor/main_test.go:197:14: undefined: exitCodeForOutput
FAIL	github.com/aniruddha/npm-ebpf-monitor/cmd/monitor [build failed]
```

This red is a **compile failure**, not a failed assertion, and that is worth
being explicit about rather than glossing.

In Go, when the defect is that a function reports nothing, there is no way to
write a test that compiles against the old signature and fails on an assertion —
the missing return value is the bug. Driving the API into existence from the
test is the standard Go form of red, and the compiler errors are specific: they
name exactly the three things the change must introduce, and nothing else. That
specificity is what a good red gives you, and it is present here.

The previous three fixes all had assertion-level reds, and each documented what
the failure message said. The distinction is recorded here so the difference in
this task's evidence file is understood rather than mistaken for a shortcut.

Raw: [`evidence/red-compile-failure.txt`](evidence/red-compile-failure.txt).

## Step 5 — implement

The four edits in [03-what-was-done.md](03-what-was-done.md), then:

```
$ go test ./cmd/monitor/ -count=1 -v
--- PASS: TestLoadInstallFeaturesUsesSessionCwd
--- PASS: TestLoadInstallFeaturesMissingCwd
--- PASS: TestRunOutputWorkerReportsWriteOutcomes            (3 subtests)
--- PASS: TestExitCodeForOutputFailsWhenSessionsWereLost     (4 subtests)
ok  	github.com/aniruddha/npm-ebpf-monitor/cmd/monitor	0.006s
```

Both pre-existing tests still pass untouched.

Raw: [`evidence/green-monitor-suite.txt`](evidence/green-monitor-suite.txt).

## Step 6 — check the root assumption

The whole failing-writer design rests on "`ENOTDIR` still fails as root". Ran it
that way explicitly rather than inferring it from the full-suite result:

```
$ sudo -n /usr/bin/go test ./cmd/monitor/ -run TestRunOutputWorkerReportsWriteOutcomes -count=1 -v
    --- PASS: .../all_writes_succeed
    --- PASS: .../all_writes_fail
    --- PASS: .../no_sessions_at_all
```

`all_writes_fail` passing as root confirms the writer genuinely failed there.

Raw: [`evidence/root-suite.txt`](evidence/root-suite.txt).

## Step 7 — verify the repository

```
$ go build ./...                             BUILD OK
$ go test -race ./... -count=1               all ok
$ sudo -n /usr/bin/go test ./... -count=1    all ok
```

`-race` matters specifically for this change: `outStats` crosses a goroutine
boundary. Clean.

Raw: [`evidence/race-suite.txt`](evidence/race-suite.txt).

## Step 8 — record the wiring

`main` cannot be unit-tested, so the part that is taken on trust was written down
rather than left implicit: the stats type, the exit function, the worker's
counting, the call site, and the shutdown block are captured verbatim in
[`evidence/wiring.txt`](evidence/wiring.txt) — with the limitation stated in
[07-findings-not-fixed.md](07-findings-not-fixed.md) rather than left for a
reader to discover.
