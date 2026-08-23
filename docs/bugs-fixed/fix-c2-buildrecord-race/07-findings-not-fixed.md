# 7. Findings not fixed

## A. The end-to-end Detector seam has no C2 regression coverage — accepted

Documented in detail in [02-tests.md](02-tests.md) and
[05-why-this-approach.md](05-why-this-approach.md). The agreed "end-to-end via
Detector" seam cannot drive the race from outside the `session` package, proven
by reverting the fix and observing the test still pass with zero races.

**Why not fixed:** widening the window would mean adding test-only hooks to
`RouteToSession` — production code shaped by test convenience, on the hottest
path in the detector. The narrow-window race is genuinely covered by slice 2 at
the `BuildRecord` boundary, which is where the unsafe read actually lived.

**If it ever needs closing:** an unexported hook (a `func()` field on `Detector`,
nil in production) called between `d.mu.RUnlock()` and `fn(session)` would let a
same-package test block there while a completion runs. Worth it only if this
class of bug recurs.

## B. `RouteToSession` still calls out with no lock held — by design, but sharp

The structural cause of C2 is untouched: `RouteToSession` reads the session
pointer under `d.mu.RLock()`, releases it, then calls `fn(session)`. Any future
reader that reaches into `*Session` from that callback, or from the completed
channel, reintroduces exactly this bug.

**Why not fixed:** holding `d.mu` across `fn(session)` would serialise every
collector event through one lock — a real throughput cost on the hot path, and a
lock-ordering hazard against `s.mu`. The correct guard is the one now in place:
`Session` exposes no way to read its state unsynchronised.

**Worth adding:** a short comment on `RouteToSession` recording why the lock is
released early, so the next reader understands the contract rather than
rediscovering it.

## C. `Session`'s exported fields are still directly reachable — Low

`Snapshot()` is the safe path, but `ID`, `PackageName`, `ProcessTree`,
`SyscallCounts` and the aggregator pointers remain exported on `Session`.
Nothing stops new code from reading them directly and racing again.

**Why not fixed:** unexporting them would ripple through `detector.go` and the
existing test suite, well beyond this fix's scope. `cmd/monitor` currently reads
only `completed.ID` (for a log line) and `sess.Cwd` (in `loadInstallFeatures`,
after the session has completed and collectors have stopped) — both benign
today, neither racing in practice.

**Suggested shape:** make the feature-carrying fields unexported and keep
identity fields public, so the compiler enforces what the comment currently asks
for.

## D. `loadInstallFeatures` reads `sess.Cwd` without the lock — Low

`cmd/monitor/main.go` calls `loadInstallFeatures(completed)`, which reads
`sess.Cwd` directly. `Cwd` is written once, in `handleExec`, before the session
is ever registered or routed to — so no writer can be racing it by the time the
output worker sees it.

**Why not fixed:** there is no race today, and `Snapshot().Cwd` is already
available if this ever needs tightening (the field was included in `Snapshot`
for exactly that reason). Noted so the next reader does not have to re-derive
that it is safe.

---

## Still open from earlier work

- **C3 — a session can be completed twice.** Critical, still open. Timeout vs.
  normal-exit race producing duplicate output; the audit also notes the timeout
  path leaks its `*time.Timer` entry in `d.timers`. **This is the next task.**
- **`bpf/vmlinux.h` is stale**; regenerating needs `bpftool`.
- **`llvm-strip` is not installed**, so `go generate ./internal/collector/...`
  needs `BPF2GO_STRIP=/usr/bin/strip`.
- **Fork handler insert side** can write a TID into the tgid-keyed map on
  `CLONE_THREAD` — see
  [`../fix-fork-tgid-lookup/07-findings-not-fixed.md`](../fix-fork-tgid-lookup/07-findings-not-fixed.md).
