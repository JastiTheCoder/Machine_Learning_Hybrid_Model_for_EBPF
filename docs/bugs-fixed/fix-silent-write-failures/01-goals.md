# 1. Goals

## The defect

Recorded as finding **A** in
[`../fix-output-filename-sanitization/07-findings-not-fixed.md`](../fix-output-filename-sanitization/07-findings-not-fixed.md),
and originally observed while fixing the filename bug.

`cmd/monitor/main.go`, before this change:

```go
func runOutputWorker(detector *session.Detector, writer *output.JSONWriter, verbose bool) {
	for completed := range detector.Completed() {
		...
		path, err := writer.Write(record)
		if err != nil {
			log.Printf("write session %s: %v", completed.ID, err)
			continue
		}
		...
	}
}
```

The function returns nothing. A failed write produces one log line among the
many the monitor emits, and then the session — every eBPF event collected during
that install, the whole point of the run — is gone. Nothing counts it, nothing
reports it at shutdown, and `main` exits zero regardless.

## Why this still matters after the filename fix

The [previous fix](../fix-output-filename-sanitization/) removed the *cause*
that had actually been observed: package specs containing `/`. It did not remove
the *category*. A write can still fail because:

- the disk fills up part-way through a capture — the single most likely failure
  during a long corpus run, and the one where losing the tail of the run silently
  is most damaging;
- the output directory is read-only, or on a filesystem that has gone read-only
  after an error;
- the path is on a full or unmounted volume.

In each case the current behaviour is identical: a log line, and a corpus that is
quietly short of the sessions the operator thinks they captured.

## Why it is worth fixing before re-capturing the corpus

The corpus re-capture is the next task. It is a long, mostly unattended run whose
entire product is a set of session files. Running it while the monitor is
incapable of telling you it lost some of them is the wrong order of operations —
the failure mode of that combination is a training set that is silently
incomplete, which is exactly the kind of defect that survives all the way into a
model's results.

## Goals

1. **Count what was persisted and what was lost.** The worker must report both,
   not just log.
2. **Say so at shutdown.** The counts must appear in the monitor's output, on
   success as well as failure — an operator should be able to read "wrote 12
   session record(s)" and compare it to the 12 installs they ran.
3. **Exit non-zero when a session was lost.** A capture is usually driven by a
   script; a log line is not a signal a script can act on, an exit status is.
4. **Do not abort the run on a single failure.** Continuing is the right
   behaviour — aborting would discard the sessions still to come, turning a
   partial loss into a total one. The change is about visibility, not
   abandonment.
5. **Change nothing else.** No collector, no detector, no output format.

## How we would know

- Goals 1 and 4 → a table-driven test driving the worker with a writer that
  always fails, asserting the failures are counted and that every session in the
  batch was still attempted.
- Goal 3 → a table-driven test on the exit-status decision.
- Goal 2 → the shutdown path, verified by inspection and recorded in
  [`evidence/wiring.txt`](evidence/wiring.txt). Its limits are stated honestly in
  [07-findings-not-fixed.md](07-findings-not-fixed.md).
- Goal 5 → the full repository suite, under `-race` and under root.
