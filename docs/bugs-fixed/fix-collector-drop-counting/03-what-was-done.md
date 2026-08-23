# 3. What was done

Five production files changed (one per collector), one production file
(`cmd/monitor/main.go`) extended, two test files extended, three new test
files added.

## Each collector — count the drop at its exact site

Identical shape applied to `process_collector.go`, `file_collector.go`,
`syscall_collector.go`, `tcp_collector.go`, `bytes_collector.go`. Using
`ProcessCollector` as the representative example:

```diff
 import (
 	...
+	"sync/atomic"
 	...
 )

 type ProcessCollector struct {
 	...
 	Events chan ProcessEvent
+
+	// dropCount counts events dropped because Events was full. Accessed via
+	// sync/atomic since it is written from Run's own goroutine and read from
+	// whichever goroutine calls DroppedEvents (typically cmd/monitor at
+	// shutdown).
+	dropCount uint64
 }
```

```diff
 		select {
 		case c.Events <- evt:
 		default:
 			// Consumer is lagging; drop rather than block.
+			atomic.AddUint64(&c.dropCount, 1)
 		}
```

```go
// DroppedEvents returns how many ProcessEvents have been dropped because
// Events was full since this collector started. See AUDIT.md H5.
func (c *ProcessCollector) DroppedEvents() uint64 {
	return atomic.LoadUint64(&c.dropCount)
}
```

The other four collectors' `DroppedEvents()` accessors are identical except
for the event-type name in the doc comment and the counted field's
receiver.

## `cmd/monitor/main.go` — report at shutdown

Added immediately after the existing H4 `DroppedRoutesForUnknownPID` report
and before the `outStats.failed` check:

```go
// Each collector drops events (rather than blocking its ring-buffer
// reader) when the consumer can't keep up -- previously invisible on
// every collector (AUDIT.md H5). Reported after Close() is fine here:
// unlike H2's pending_opens counter, these live in the collector's own
// Go memory, not a BPF map, so Close() doesn't invalidate them.
for _, d := range []struct {
	name    string
	dropped uint64
}{
	{"process", processCollector.DroppedEvents()},
	{"syscall", syscallCollector.DroppedEvents()},
	{"file", fileCollector.DroppedEvents()},
	{"tcp", tcpCollector.DroppedEvents()},
	{"bytes", bytesCollector.DroppedEvents()},
} {
	if d.dropped > 0 {
		log.Printf("%d %s event(s) were dropped: the consumer was lagging behind "+
			"the ring buffer (AUDIT.md H5)", d.dropped, d.name)
	}
}
```

## Test files

- `internal/collector/process_collector_test.go` — added
  `TestProcessCollectorCountsDroppedEvents` (non-blocking fill, relative
  `before`/`after` assertion — see [04](04-how-it-was-done.md) for why this
  one differs from the other four).
- `internal/collector/file_collector_test.go` — added
  `TestFileCollectorCountsDroppedEvents` (blocking fill, absolute-zero
  baseline).
- `internal/collector/syscall_collector_test.go` — new file, added
  `TestSyscallCollectorCountsDroppedEvents` (same shape as file's).
- `internal/collector/tcp_collector_test.go` — new file, added
  `TestTcpCollectorCountsDroppedEvents` (same shape).
- `internal/collector/bytes_collector_test.go` — new file, added
  `TestBytesCollectorCountsDroppedEvents` (same shape).

## Not changed

Every collector's decode logic, BPF C source, `Run` loop control flow
beyond the one added `atomic.AddUint64` line, `Close`/`NewXCollector`
constructors, channel capacities, `internal/session/*`, `internal/output/*`,
`internal/features/*`, and any pre-existing test in these files.
`internal/collector/bytes_collector.go` and `internal/collector/collector.go`
remain `gofmt`-unclean at the exact spots they already were before this
change (see [04-how-it-was-done.md](04-how-it-was-done.md)) — left alone,
consistent with the H3 fix's precedent of not reformatting pre-existing
debt as a drive-by.
