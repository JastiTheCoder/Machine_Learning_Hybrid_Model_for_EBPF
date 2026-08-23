# 2. Tests

Five test functions across two packages, in four slices. The oracle throughout
is **`go test -race`** — for a data race, reasoning about the code is not
evidence and a plain `go test` can pass by luck.

## Seams — agreed before any test was written

The TDD skill requires it ("No test is written at an unconfirmed seam"). Four
were proposed and **all four confirmed**, along with the choice of fix:

| Seam | Outcome |
|---|---|
| `BuildRecord` under concurrent writers | ✅ **the test with teeth** — 10 races → 0 |
| `Session.Snapshot()` consistency | ✅ covered, slices 1 and 4 |
| End-to-end via Detector | ⚠️ **could not reproduce the race** — see below |
| Aggregators individually | ✅ covered as a guard, slice 4 |

---

## Slice 1 — `TestSnapshotIsIndependentOfLaterMutation`, `TestSnapshotCopiesSessionIdentity`

The first asserts the defining property of a snapshot: writes to the session
*after* the snapshot was taken must not alter it.

This is the assertion a naive implementation fails. `SyscallCounts` is a map, so
returning it directly hands the caller a live reference into the session — the
snapshot would then keep changing as collectors write, which is both wrong and
the exact aliasing that makes the crash possible.

It is also deliberately not tautological: it compares the snapshot against
values captured *before* a mutation that provably happened, and then takes a
second snapshot to confirm the new writes **are** visible — so the test cannot
pass by `Snapshot` simply returning stale or empty data.

**Result: achieved.** Red (`session.Snapshot undefined`) → both pass.

## Slice 2 — `TestBuildRecordIsSafeWhileSessionIsStillBeingWrittenTo`

**The test with teeth.** Eight goroutines run the same calls the detector makes
for real collector events (`AddProcess`/`AddSyscall`/`AddFile`/`AddTCP`/`AddBytes`)
while a ninth calls `BuildRecord` in a loop.

It also guards against a false pass: after the writers finish it asserts the
record actually contains a session ID and a non-zero syscall total, so a
`BuildRecord` that returned an empty record could not satisfy it.

**Result: achieved — this is the headline measurement.**

Before: **10 distinct `WARNING: DATA RACE` reports**, including the exact crash
vector:

```
Write at 0x00c0000c58c0 by goroutine 9:
  runtime.mapassign_faststr()
  session.(*Session).AddSyscall()      session.go:97

Previous read at 0x00c0000c58c0 by goroutine 17:
  runtime.mapaccess1_faststr()
  output.buildSyscallFeatures()        json_writer.go:255
  output.BuildRecord()                 json_writer.go:136
```

`mapassign` racing `mapaccess` on the same address is precisely what the Go
runtime aborts on. After: **0 races.**

Raw: [`slice2-red.txt`](evidence/slice2-red.txt), [`slice2-green.txt`](evidence/slice2-green.txt).

## Slice 3 — `TestBuildRecordOnCompletedSessionWhileCollectorsStillWrite` — **the seam that did not work**

Intended as the production-faithful reproduction: drive a real `Detector`
through its exported API, submit an `npm install` exec to create a session, keep
submitting collector events for its PIDs, complete the session by exiting its
processes, then `BuildRecord` the completed session.

It passed. Rather than accept that as success, the guard was checked for teeth
by **reverting the fix** — restoring `BuildRecord`'s direct field reads — and
re-running:

```
=== slice 3 against the REVERTED (buggy) BuildRecord ===
DATA RACE reports: 0
ok  github.com/aniruddha/npm-ebpf-monitor/internal/output  1.008s
```

**It still passed. The test has no teeth for C2.**

The reason is structural, not a flaw in the test's construction: completing a
session calls `unregisterSession`, which removes its PIDs from
`d.pidToSession`. From that moment `RouteToSession` finds nothing and returns
early, so the writers stop touching the session almost immediately. The genuine
window is the handful of instructions between `RouteToSession`'s
`d.mu.RUnlock()` and its `fn(session)` call, and it cannot be widened or hit
reliably from outside the package without adding instrumentation hooks to
production code.

The test was **relabelled rather than deleted**, with the negative result
written into its own doc comment. It still earns its place: it is the only test
that drives a record all the way from raw collector events, through the
detector, to a finished `SessionRecord`. It is simply not the C2 regression
test, and the comment now says so explicitly so nobody later mistakes it for one.

Raw: [`slice3-e2e.txt`](evidence/slice3-e2e.txt),
[`slice3-teeth-check.txt`](evidence/slice3-teeth-check.txt).

## Slice 4 — `TestSnapshotIsRaceFreeUnderConcurrentWriters`

Pins the new boundary's concurrency guarantee directly rather than only through
`BuildRecord`: six writer goroutines against a reader calling `Snapshot()` and
reading the cloned map, under `-race`.

**This is a guard, not a red** — `Snapshot` took `s.mu` from the moment it was
written in slice 1, so it passed immediately, and the source comment says so.
It is kept because this guarantee is `Snapshot`'s entire reason to exist: if a
later change drops the lock or returns a live map instead of a clone, this fails
where a correctness-only test would not.

**Result: achieved.**

---

## Goal coverage

| Goal | Covered by | Achieved |
|---|---|---|
| 1 — no unsynchronised reads | Slice 2 (10 → 0 races) | yes |
| 2 — internally consistent record | Slice 1 (single lock acquisition) | yes |
| 3 — record does not alias live state | Slice 1 (independence) | yes |
| 4 — mutex stays private | `Snapshot()` is a method; `mu` unexported | yes |
| 5 — proven with the race detector | Slices 2 and 4 | yes |
| 6 — nothing else changes | full `-race` + root suites | yes |
