# 1. Goals

## The defect

`AUDIT.md` C2. `internal/output/json_writer.go`'s `BuildRecord` read all of the
following with **no lock**:

```go
record.ProcessTree = sess.ProcessTree
record.Syscalls    = buildSyscallFeatures(sess.SyscallCounts)
record.TimedOut    = sess.TimedOut
if sess.FiletopAgg != nil { record.Filetop  = sess.FiletopAgg.Snapshot() }
if sess.DirCounts  != nil { record.Opensnoop = sess.DirCounts.ToMap() }
if sess.TCPAgg     != nil { record.TCP      = sess.TCPAgg.Counts() }
if sess.NGramCtr   != nil { record.Patterns = sess.NGramCtr.Snapshot() }
```

Meanwhile **every** mutator in `internal/session/session.go` opens with
`s.mu.Lock()`: `AddProcess`, `AddSyscall`, `AddFile`, `AddTCP`, `AddBytes`,
`Complete`, `TrackPID`, `ExitPID`.

Verified directly rather than taken from the audit — of the four aggregators,
only one protects itself:

| Aggregator | Own mutex? | Protected by |
|---|---|---|
| `FiletopAggregator` | **yes** (`mu sync.Mutex`) | itself |
| `DirCounts` | no | `session.mu` only |
| `TCPAggregator` | no — and holds **4 maps** | `session.mu` only |
| `NGramCounter` | no | `session.mu` only |

## Why it crashes rather than merely corrupts

Two of the racing structures are Go maps: `Session.SyscallCounts
map[features.SyscallCategory]int`, read directly by `buildSyscallFeatures`, and
`TCPAggregator`'s `LocalIPs`/`RemoteIPs`/`LocalPorts`/`RemotePorts`, read by
`Counts()`.

Go's runtime detects concurrent map access and aborts the process with
`fatal error: concurrent map read and map write`. It is not a panic — it cannot
be recovered. Every session still being collected in that run is lost, and the
monitor exits mid-capture.

The non-map fields (`ProcessTree` string append, `DirCounts`' ints,
`NGramCounter`'s window) degrade more quietly: torn reads and inconsistent
feature vectors, which for this project means silently wrong training data.

## Why it is reachable in production

`Detector.RouteToSession` (`internal/session/detector.go:117`):

```go
d.mu.RLock()
session := d.pidToSession[pid]
d.mu.RUnlock()          // <-- lock released here
if session == nil { return }

d.ensureLivePID(session, pid)
fn(session)             // <-- AddSyscall / AddFile / AddTCP, no detector lock held
```

Nothing holds a lock across `fn(session)`. Concurrently, `cmd/monitor`'s output
worker receives that same `*Session` from `detector.Completed()` and calls
`BuildRecord` on it from a different goroutine. If a session completes — last
PID exits, or the 120s timeout fires on the runtime's timer goroutine — while a
routing call is in flight, both touch the same session simultaneously.

## Why the existing test suite never caught it

`TestConcurrency` in `session_test.go` spawns 100 goroutines, but **every one of
them is a writer** (`AddProcess`, `AddSyscall`, `AddFile`, …). All writers take
`s.mu`, so they mutually exclude and no race exists between them. The test never
runs a reader concurrently, so it passes cleanly despite C2 — the third time in
this audit series that green coverage structurally could not catch the bug under
it.

## Goals

1. **`BuildRecord` must never touch session state unsynchronised.**
2. **The record must be internally consistent** — all fields sampled at one
   instant, not smeared across a mutating session.
3. **A returned record must not alias live session state**, so a caller holding
   it cannot observe it change underneath them.
4. **Keep the mutex private.** Fixing this by exporting the lock would push the
   discipline onto every future caller.
5. **Prove it with the race detector**, not by reasoning about the code.
6. **Nothing else changes** — no BPF, no schema, no collector.

## How we would know

- Goals 1, 5 → a test running collector writes against `BuildRecord` under
  `go test -race`, red before and green after.
- Goals 2, 3 → a snapshot-independence test: mutate the session after taking a
  snapshot and assert the snapshot does not move.
- Goal 4 → `mu` stays unexported; the fix is a method on `Session`.
- Goal 6 → full repository suite, `-race` and under root.
