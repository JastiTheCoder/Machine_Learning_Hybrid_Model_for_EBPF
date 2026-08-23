# 3. What was done

One production file changed: `cmd/monitor/main.go`. Four edits.

## Edit 1 — the stats type and the exit decision

```go
// outputStats records what the output worker managed to persist, so that
// shutdown can report it and set the exit status accordingly.
type outputStats struct {
	written int
	failed  int
}

// exitCodeForOutput returns the process exit status implied by the output
// worker's results. Any lost session is a failed run: a capture is usually
// driven by a script, and an incomplete corpus that exits zero is worse than
// one that stops loudly.
func exitCodeForOutput(stats outputStats) int {
	if stats.failed > 0 {
		return 1
	}
	return 0
}
```

`exitCodeForOutput` is a separate function rather than an `if` inside `main`
because `main` cannot be unit-tested — it loads BPF and calls `os.Exit`.
Extracting the *decision* leaves a testable pure function and reduces what has
to be taken on trust to a single call.

## Edit 2 — the worker signature

```diff
-func runOutputWorker(detector *session.Detector, writer *output.JSONWriter, verbose bool) {
-	for completed := range detector.Completed() {
+func runOutputWorker(completed <-chan *session.Session, writer *output.JSONWriter, verbose bool) outputStats {
+	var stats outputStats
+
+	for completed := range completed {
```

Two changes in one line, for two different reasons.

The **return value** is the feature: the worker now reports what it did.

The **parameter narrowing** is what makes it testable. The worker took a
`*session.Detector` but used exactly one method on it, `Completed()`. A test
would otherwise have had to construct a detector and drive real process events
through it just to deliver a session to a function that never wanted a detector
in the first place. Taking the channel makes the dependency honest and the test
a three-line helper.

## Edit 3 — counting

```diff
 		path, err := writer.Write(record)
 		if err != nil {
+			// Keep going: aborting a long capture over one bad write would
+			// discard the sessions that are still to come. The count is what
+			// makes the loss visible at shutdown.
+			stats.failed++
 			log.Printf("write session %s: %v", completed.ID, err)
 			continue
 		}
 
+		stats.written++
 		if verbose {
 			log.Printf("wrote session record: %s", path)
 		}
 	}
+
+	return stats
 }
```

The `continue` stays. The comment explains why, because "keep going after an
error" looks like the bug being fixed and a future reader deserves to know it is
deliberate.

## Edit 4 — the call site and shutdown

```diff
+	// Safe to read after wg.Wait(): the WaitGroup establishes happens-before.
+	var outStats outputStats
 	startTrackedGoroutine(&wg, func() {
-		runOutputWorker(detector, writer, *verbose)
+		outStats = runOutputWorker(detector.Completed(), writer, *verbose)
 	})
```

```diff
 	closeAndLog("process collector", processCollector)
+
+	if outStats.failed > 0 {
+		log.Printf("LOST %d of %d session(s): they were collected but could not be written",
+			outStats.failed, outStats.written+outStats.failed)
+	} else {
+		fmt.Printf("Wrote %d session record(s).\n", outStats.written)
+	}
+
+	os.Exit(exitCodeForOutput(outStats))
 }
```

`outStats` is written on the worker goroutine and read on the main goroutine
after `wg.Wait()`. That is not a data race: `wg.Wait()` returning happens-after
the `wg.Done()` deferred by `startTrackedGoroutine`, which happens-after the
assignment. The comment records the reasoning so it is not "fixed" later by
someone adding a mutex, and `go test -race ./...` is clean.

The success branch prints unconditionally rather than only under `-verbose`.
Goal 2 is that an operator can compare the count to the number of installs they
ran; a count they have to opt into does not achieve that.

## `cmd/monitor/main_test.go`

Added `strconv` and the `internal/output` import, two helpers (`newFailingWriter`,
`feedSessions`) and the two tests from [02-tests.md](02-tests.md). No existing
test was modified.

## Not changed

No BPF source, no regenerated object, no output format, no collector or detector
code. `internal/output` was not touched by this change at all.
