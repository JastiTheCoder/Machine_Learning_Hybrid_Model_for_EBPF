# 3. What was done

One new test file, one existing test file corrected. No production code
changed.

## `cmd/monitor/e2e_regression_test.go` (new)

Shared infrastructure:

- `buildBinary`/`buildMonitorBinary`/`buildLabelerBinary` — compile
  `./cmd/monitor` and `./cmd/dataset/labeler` once per test process
  (`sync.Map` + `sync.Once` keyed by import path) via `go build`, so tests
  run the exact artifact an operator would run rather than a
  reimplementation of `main()`.
- `syncBuffer`, `monitorProc`, `startMonitor`, `stopMonitor` — launch the
  compiled monitor as a real subprocess, wait for its startup line, and
  later signal it with a real `SIGINT` and read its real exit code.
- `shortTempDir`, `newLocalPackage`, `npmPack`, `copyFile`, `runNpmInstall`,
  `requireRootAndNpm` — build and install small, synthetic, network-free npm
  fixtures, matching the precedent already set by
  `internal/features/filetop_npm_e2e_test.go`'s `newNpmFixture`.
- `waitForSessionWithPackageName`, `readSessionJSON` — locate and decode a
  specific session JSON by its `package_name`, tolerant of unrelated
  sessions the monitor may also capture from ambient system npm activity.

Three tests (full detail in [02-tests.md](02-tests.md)):

- `TestMonitorEndToEnd_PathLikeInstallIsCapturedTreeAndSanitized`
- `TestMonitorEndToEnd_BenignAndMaliciousFixturesAreLabeledCorrectly`
- `TestMonitorEndToEnd_ExitsNonZeroAndReportsLossWhenOutputCannotBeWritten`

## `internal/session/router_test.go` (corrected)

`TestRouter_UnknownPID` gained one synchronization step:

```diff
 	waitForWaitGroup(t, &senders, "unknown pid senders did not complete")

+	waitForCondition(t, func() bool {
+		return detector.DroppedRoutesForUnknownPID() == 3
+	}, "DroppedRoutesForUnknownPID() did not reach 3 within 1s")
+
 	syscallCount, homeCount, fileProcesses, tcpTransitions, livePID := snapshotSession(session, session.NpmPID)
```

Nothing else in the test changed — the existing assertions (syscall/home/file/tcp
counts, live-PID status, the final `DroppedRoutesForUnknownPID() != 3` check)
are all unmodified; they are simply now evaluated after the router has
actually finished processing all three events, not merely after three
channel sends returned.

## Not changed

Every production file across all twelve prior fixes; every BPF `.bpf.c`
source; every other existing test in the repository; `Router.Run`'s
dispatch loop itself (the subject of the flake, not the fix -- see
[05-why-this-approach.md](05-why-this-approach.md) for why the test, not the
router, was the right thing to change).
