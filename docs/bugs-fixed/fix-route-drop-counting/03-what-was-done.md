# 3. What was done

Two production files changed, two test files extended, one project doc
corrected.

## `internal/session/detector.go` — count and log the drop

Added a `routeDropCount uint64` field to `Detector` (accessed via
`sync/atomic`, since `RouteToSession` only takes `d.mu`'s *read* lock, not
its write lock — matching the same reasoning `TestSnapshotIsRaceFreeUnderConcurrentWriters`-style
code in this package already applies elsewhere):

```diff
 	d.mu.RLock()
 	session := d.pidToSession[pid]
 	d.mu.RUnlock()
 	if session == nil {
+		atomic.AddUint64(&d.routeDropCount, 1)
+		d.logf("dropped event for pid=%d: no session registered (AUDIT.md H4)", pid)
 		return
 	}
```

Added the accessor:

```go
// DroppedRoutesForUnknownPID returns how many times RouteToSession has been
// called for a PID with no registered session since this detector was
// created. See RouteToSession's doc comment and AUDIT.md H4.
func (d *Detector) DroppedRoutesForUnknownPID() uint64 {
	return atomic.LoadUint64(&d.routeDropCount)
}
```

`RouteToSession`'s doc comment was expanded to explain *why* this drop
happens (the cross-channel ordering gap) rather than just that it can.

## `cmd/monitor/main.go` — report at shutdown

```go
if dropped := detector.DroppedRoutesForUnknownPID(); dropped > 0 {
	log.Printf("%d syscall/file/TCP event(s) were dropped: no session was registered yet "+
		"for their pid (AUDIT.md H4 -- a cross-channel ordering race, not a crash)", dropped)
}
```

Placed alongside the existing `pending_opens` insert-failure report (H2) and
`LOST N of M session(s)` report — the same "count it, report it at shutdown,
never fail silently" shape used throughout this fix series. No `Close()` or
map-FD ordering concern here (unlike H2's `pending_opens` counter): this
counter lives in `Detector`'s own memory, not a BPF map, so it can be read at
any point in the shutdown sequence, before or after any collector closes.

## `context/architecture.md` — correct the false claim

The paragraph asserting that the router's priority pattern prevents dropped
syscall events for a brand-new PID was rewritten to state the true,
narrower guarantee, name the audited gap (H4), and point at this fix's
counter/logging as what closes the "silent" half of the problem. See the
diff in this task's commit; the surrounding code snippet (a simplified
excerpt of `Router.Run`) was left as-is since it accurately reproduces the
actual `select` structure — only the prose claiming a guarantee about what
that structure accomplishes was wrong.

## Test files

- `internal/session/detector_test.go` — added
  `TestRouteToSessionCountsAndLogsDropsForUnknownPID`.
- `internal/session/router_test.go` — extended `TestRouter_UnknownPID` with
  one assertion on `DroppedRoutesForUnknownPID()`.

## Not changed

`router.go`'s `select` structure (the subject of H4's code claim, but not
what this fix changes — see [01-goals.md](01-goals.md) and
[05-why-this-approach.md](05-why-this-approach.md)), every `handle*` method,
`HandleProcess`, session/output/BPF code, and every other test's assertions.
