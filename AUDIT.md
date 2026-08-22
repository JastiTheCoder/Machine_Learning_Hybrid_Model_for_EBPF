# npm-ebpf-monitor — Code Audit

**Date:** 2026-08-22
**Scope:** `src/npm-ebpf-monitor` (the eBPF kernel programs, the Go collector/session/
feature/output layers, the `cmd/dataset/*` CLI tools, the test fixtures, and repo
hygiene). Vendored third-party reference projects under `tools/` (cilium-ebpf,
ecapture, libbpf-bootstrap, tracee) are out of scope.

**Method:** Full read of every source file in the areas above, cross-checked against
the two architecture docs (`context/architecture.md`,
`src/npm-ebpf-monitor/docs/architecture_deep_dive.md`) claim-by-claim. The most severe
findings below were independently re-verified by direct file reads (marked
*"confirmed by direct read"*).

## What this system does

`npm-ebpf-monitor` traces an `npm install` from four CO-RE eBPF programs
(`process_tracer`, `syscall_tracer`, `file_monitor`, `tcp_monitor`), all sharing one
`tracked_pids` hash map seeded by the process tracer. Events flow through per-program
ring buffers into five Go collector goroutines, then through a single router goroutine
into a `Detector` that maintains one `Session` per npm root PID. Each session
accumulates behavioral counters (file/dir access, TCP state, syscall categories,
n-gram patterns) that get flattened into a 36-field QUT-DV25-schema feature vector,
written as JSON, and later exported to a labeled CSV for Random Forest training. The
overall design (BPF probes → ring buffers → collectors → router → session state
machine → feature aggregators → JSON/CSV) is sound and mostly matches its own
documentation. The findings below are the places where the implementation falls short
of that design or of the documentation's claims.

---

## Critical

### C1. `write_processes`/`read_processes` are structurally broken — every session ever captured has this defect

`bpf/file_monitor.bpf.c:257` hardcodes `evt->flags = 0` in the `sys_exit_openat`
probe. The `sys_enter_openat` probe (`bpf/file_monitor.bpf.c:202-224`) never reads
`openat`'s third argument (`ctx->args[2]`, the `flags` int), and `struct pending_open`
(the type used to carry state between the enter and exit probes) has no field to hold
it even if it were read. *(Confirmed by direct read.)*

Downstream, `internal/features/filetop_aggregator.go`'s `Add()` computes:

```go
mode := event.Flags & syscall.O_ACCMODE
if mode == syscall.O_RDONLY { a.readPIDs[event.Pid] = true }
if mode == syscall.O_WRONLY || mode == syscall.O_RDWR || (event.Flags&syscall.O_CREAT != 0) {
    a.writePIDs[event.Pid] = true
}
```

Since `event.Flags` is always `0`, and `syscall.O_RDONLY == 0` on Linux, `mode ==
O_RDONLY` is **always true** — every tracked file open is counted as a read, and the
write branch can never fire. `write_processes` — a required field in the QUT-DV25
schema (`internal/output/validator.go`'s `REQUIRED_FIELDS`) — is silently `0` in every
session on record, and `read_processes` is inflated to equal `file_access_processes`.

**Why it matters:** this isn't a crash or an edge case — it's a systematic defect in
every session file the tool has ever produced, corrupting one of the 36 features the
whole pipeline exists to compute, with no error or warning anywhere to surface it. A
decode-level test asserting `FileEvent.Flags` reflects a real `openat()` call's flags
would have caught this immediately; no such test exists (see [Test coverage](#test-coverage-gaps)).

**Fix direction:** read `ctx->args[2]` in `sys_enter_openat`, add a `flags` field to
`pending_open`, copy it through in `sys_exit_openat`.

---

### C2. `BuildRecord` reads session state with no locking — can crash the process or corrupt output — FIXED

`internal/output/json_writer.go:114-146` (`BuildRecord`) reads `sess.SyscallCounts`,
`sess.DirCounts.ToMap()`, `sess.TCPAgg.Counts()`, `sess.NGramCtr.Snapshot()`,
`sess.ProcessTree`, and `sess.TimedOut` **without ever calling `sess.mu.Lock()` (or
even `RLock()`)**. *(Confirmed by direct read.)*

Every writer path that mutates this same state — `AddSyscall`, `AddFile`, `AddTCP` in
`internal/session/session.go` — takes `s.mu.Lock()` first. `DirCounts`,
`TCPAggregator`, and `NGramCounter` have **no mutex of their own** (unlike
`FiletopAggregator`, which does); they rely entirely on `session.mu` for safety. Since
`BuildRecord` never takes that lock, it is an unsynchronized concurrent read against
those unsynchronized writes.

This is reachable in production: `internal/session/detector.go`'s `RouteToSession`
fetches the session pointer under `d.mu.RLock()`, releases it, then calls
`fn(session)` (e.g. `AddSyscall`) with no further locking of its own. If the
session's timeout timer fires and completes+unregisters+sends the same session to
`completedSessions` in that same window, the output worker (`cmd/monitor/main.go`)
can begin `BuildRecord` on a session an in-flight `RouteToSession` call is still
mutating.

**Why it matters:** in Go, concurrent unsynchronized map writes (e.g. inside
`DirCounts`/`TCPAggregator`'s internal maps) are a `fatal error: concurrent map
writes` — an unrecoverable process crash that loses every in-flight session for that
capture run. At best it silently corrupts a written feature vector. Not exercised by
any test — `TestConcurrency` in `session_test.go` only tests concurrent writers
against each other, never a concurrent `BuildRecord`-style read.

**FIXED.** Confirmed with the race detector before fixing: a test driving collector
writes against `BuildRecord` reported **10 distinct data races**, including the crash
vector itself — `runtime.mapassign_faststr` in `Session.AddSyscall` racing
`runtime.mapaccess1_faststr` in `buildSyscallFeatures`. The fix adds
`Session.Snapshot()`, which takes `s.mu` once and returns a value struct with cloned
maps; `BuildRecord` consumes that instead of reaching into the session, so every field
comes from one coherent instant and nothing aliases live state. `Session.mu` stays
unexported. After: 0 races. Details:
[`docs/fix-c2-buildrecord-race/`](docs/fix-c2-buildrecord-race/).

One honest caveat recorded there: the end-to-end Detector seam could **not** reproduce
this race (verified by reverting the fix and watching the test still pass), because
`unregisterSession` removes the session's PIDs the moment it completes. The regression
test with teeth is at the `BuildRecord` boundary.

---

### C3. A session can be completed twice — timeout vs. normal-exit race

`internal/session/detector.go:292-320` (`handleExit`) and `detector.go:417-441`
(the `time.AfterFunc` timeout callback) are two independent completion paths running
on **different goroutines** — the router goroutine and the Go runtime's timer
goroutine — and neither checks whether the other has already completed the session.
*(Confirmed by direct read of `detector.go:400-452`.)*

- `handleExit` calls `stopSessionTimer` then `session.Complete()`, `unregisterSession`,
  then sends on `completedSessions`.
- The timeout callback independently does the same sequence, gated only by
  `completedMu.RLock()` — which prevents a send *after the channel is closed*, but
  **not** a double-send between the two paths, since both only ever take the *read*
  side of that `RWMutex` simultaneously.
- `timer.Stop()` (called from `stopSessionTimer`) is a no-op if the timer has already
  fired — it cannot cancel a callback that's already running.

If the last live PID exits at nearly the same moment the session timeout deadline
arrives, both goroutines can call `unregisterSession` + `completedSessions <-
session` for the same `*Session`. The output worker then runs `BuildRecord`/`Write`
twice for one install — producing a duplicate (and, via C2, potentially torn) JSON
file. Not covered by `TestSessionTimeout` (`detector_test.go`), which only exercises
pure-timeout completion with no competing EXIT event.

**Compounding leak:** the timeout callback also never calls `stopSessionTimer` /
`delete(d.timers, npmPID)` on itself — only the normal-exit path does. Every session
that completes via timeout leaves its `*time.Timer` entry in `d.timers` permanently
(see H1 below).

---

### C4. Genuinely malicious test fixtures get exported to the training CSV labeled benign — FIXED

`cmd/dataset/labeler/main.go`'s `labelFor` only assigns `label=1` (malicious) if the
session's filename or `package_name` contains the literal substring `"suspicious"`.
The four attack-simulation fixtures added alongside it — `crypto-miner-test`,
`env-stealer-test`, `ci-secret-grabber-test`, and `reverse-shell-test` — do **not**
contain that substring, so they default to `label=0` (benign). The same fallback
heuristic is duplicated in `cmd/dataset/validator/main.go`'s `derivedLabel`.

This compounds with two more gaps:
- `BuildRecord` never sets `Session.Label` at all — confirmed empirically, every file
  under `sessions/*.json` has `"label": null`.
- `internal/output/json_writer.go`'s `ToCSVRow` defaults a `nil` label to `"0"` with
  no warning or error when writing the CSV row.

So if the labeler is ever skipped, or simply misses one of these fixture names (as it
currently does for four of the five attack simulations), the exporter writes
`label=0, severity_score=0` straight to the training CSV — no validation gate, no
skip, no log line.

**Why it matters:** this is the exact ground-truth signal the whole project exists to
produce for Random Forest training. A silent benign-mislabel of real malicious
samples is worse than a crash: it actively corrupts the dataset with no diagnostic
trail, and neither `cmd/dataset/validator/main.go`'s "no file may have all-zero
features" rule nor any other check catches it (a mislabeled row still has legitimate
non-zero behavioral features — only the label is wrong).

**Fix direction:** the labeler should use an explicit fixture-name → label mapping
(or a `severity`/`category` field embedded at capture time) instead of a single
substring heuristic, and the exporter should refuse or flag rows where `Label ==
nil` rather than silently defaulting to `0`.

**FIXED.** Measured against this project's own 13-session corpus, the old heuristic
produced `11 benign, 2 malicious` where ground truth is `3 benign, 10 malicious` —
**8 of the 10 malicious samples were labelled benign** (independently reproducible;
see the linked docs). The fix adds `internal/dataset`, a declared fixture → ground-truth
table shared by both the labeler and the validator, which returns `ErrUnknownPackage`
for an undeclared package rather than defaulting. `ToCSVRow` now returns an error when
`Label == nil` instead of writing `"0"`, the exporter excludes those rows and exits
non-zero, and the validator gained a Rule 4 that fails when any session has no
resolvable label. The corpus now labels `3 benign, 10 malicious`, and the exported CSV
carries that distribution exactly. Details:
[`docs/fix-c4-ground-truth-labels/`](docs/fix-c4-ground-truth-labels/).

---

## High

### H1. `d.timers` map leaks one entry per session that times out

Already noted under C3: `stopSessionTimer` (the only place that does
`delete(d.timers, npmPID)`) is called from the normal-exit path but never from the
timeout callback itself. Any fraction of captured installs that hang or time out
leaks a `d.timers` entry for the life of the process — effectively unbounded growth
for a tool whose purpose is running large batches of installs for dataset generation.

### H2. `pending_opens` (BPF map) leaks if a tracked process is killed mid-syscall

`bpf/file_monitor.bpf.c` inserts into `pending_opens` at `sys_enter_openat`
(keyed by `pid_tgid`) and only removes the entry in `sys_exit_openat`. If a process
is SIGKILLed while blocked inside `openat`, `sys_exit_openat` never fires and the
entry is never removed. The map is bounded (4096 entries) and `bpf_map_update_elem`'s
return value is never checked at the insert site, so under sustained leakage the map
silently starts dropping new file events with no signal to userspace.

### H3. Dead `Detector.Run()`/`Submit*` machinery — and it's what most of `detector_test.go` actually tests

`cmd/monitor/main.go` starts both `detector.Run(ctx)` and `router.Run(ctx)`. But
`Router.Run` calls `detector.HandleProcess`/`detector.RouteToSession` **directly**,
never through `Detector`'s `SubmitProcess/SubmitSyscall/SubmitFile/SubmitTCP` methods.
A repo-wide grep confirms those `Submit*` methods are called only from
`detector_test.go` — never from production code. `Detector.Run()`'s internal event
channels are therefore never fed in production; that goroutine just blocks on
`ctx.Done()` forever.

The consequence for test coverage: `TestDetector_NpmInstallLifecycle`,
`TestDetector_ConcurrentSessionCwds`, `TestDetector_SeedsTrackedRootPIDAndCompletesOnRootExit`,
`TestDetector_ForkOnlyChildrenDoNotBlockCompletion`, and `TestSessionTimeout` all drive
the detector via `Submit*` + `detector.Run(ctx)` — a path the real binary never
executes. Only `router_test.go` exercises the actual production call path, and its
lifecycle-edge-case coverage (timeout races, fork-then-immediate-exit, PID reuse) is
much thinner. This also means there's no `SubmitBytes`/`bytesEvents` in `Detector` at
all — a leftover from before `BytesCollector` existed, never fully wired up or
removed.

### H4. Router's "priority" pattern doesn't guarantee the ordering the docs claim it does

`context/architecture.md` states that process events are given priority in the
router's outer `select` specifically to prevent syscall events for a brand-new PID
from being dropped before its session exists. The actual mechanism only prefers
`procCh` if a message is *already buffered* on it at select time; if not, the inner
`select` treats all five channels equally (no priority). More fundamentally, the five
event types arrive via five *independent* ring-buffer-reading goroutines, so there is
no cross-channel delivery-order guarantee at all regardless of the select structure —
a syscall event for a brand-new PID can physically be read and channeled before the
corresponding EXEC event. When that happens, `RouteToSession` finds no session for
that PID and silently, permanently drops the event (no retry, no counter, no log by
default). The priority pattern lowers the odds of this; it does not eliminate the
race the docs say it eliminates.

### H5. Silent event drops under backpressure are never counted or logged

All five collectors (`process_collector.go`, `syscall_collector.go`,
`file_collector.go`, `tcp_collector.go`, `bytes_collector.go`) use the same pattern:

```go
select {
case c.Events <- evt:
default:
    // Consumer is lagging; drop rather than block.
}
```

There is no counter, metric, or log line anywhere when the `default` branch fires. A
single `lodash` install generates roughly 13,000 syscall events against a
4096-entry-deep channel buffer, so it's entirely plausible for real bursts to drop
events with zero indication to the operator or to the ML pipeline that a session's
feature counts are undercounted.

### H6. `ml_handoff.md`'s CSV column table is self-contradictory; the code itself is correct

`internal/output/json_writer.go`'s `ToCSVRow` and `cmd/dataset/exporter/main.go`'s
`csvHeader` agree with each other exactly: 39 columns (`package_name`, `label`, 5
filetop, 3 install, 7 opensnoop, 5 tcp, **6** syscall fields — `unknown_ops`
deliberately excluded — 10 pattern fields, `severity_score`).
`cmd/dataset/validator/main.go` even comments explicitly: *"Syscalls (6 of the 7 —
unknown_ops excluded from QUT-DV25)."* The code is internally consistent.

`docs/ml_handoff.md`'s column table (lines 45-92), however, inserts a phantom row 29
`unknown_ops` that doesn't exist in the real CSV, then garbles its final row into
`| 39–1: `p10_error_handle` then | severity_score | derived (mirrors label) |` — an
invalid index merging two columns into one row — and its own "self-correcting"
footnote claims the syscall group has 7 fields with `unknown_ops` at column 29,
which is also wrong (real column 29 is `p1_file_metadata`). Anyone hand-verifying the
CSV against the doc, or writing a strict-schema loader against the doc's table
instead of the actual header row, would be misled. The doc's table needs the phantom
row deleted and the final row split correctly; the code needs no change.

### H7. PID-reuse aliasing — no epoch/generation guard on `pidToSession`

`handleExec` looks up sessions purely by PID number, with no generation counter.
Given H5's confirmed possibility of dropped EXIT events, if an EXIT for some tracked
child PID is ever lost, that PID's `pidToSession` entry survives until its *session*
eventually completes or times out. If the OS reuses that PID for a brand-new,
unrelated `npm install` in the meantime, `handleExec` will find the stale session and
silently fold the new install's events into it instead of creating a fresh one —
cross-contaminating two installs' feature vectors.

---

## Medium

- **`internal/output/writer.go` is a dead stub.** `NewWriter`/`WriteResults` are
  never called anywhere in the codebase (production code uses
  `output.NewJSONWriter`/`BuildRecord` instead); `WriteResults` unconditionally
  returns `nil` regardless of its input. No test references it.
- **`internal/features/aggregator.go`** and **`internal/collector/collector.go`** are
  similarly dead `TODO` stubs with no callers — vestigial scaffolding that adds
  confusion about which type actually does the aggregating/collecting (it's
  `Session` + the individual aggregators, and the five concrete collectors,
  respectively).
- **`scripts/compare_packages.sh` / `compare_packages_multi.sh` reference a stale
  binary name.** Both hardcode `BINARY="$PROJECT_ROOT/npm-ebpf-monitor"`, but the
  actual build output (per the `Makefile`'s `BINARY_NAME` and what's committed at the
  repo root) is named `monitor`. Both scripts currently fail their own pre-flight
  "binary not found" check and exit immediately.
- **`Makefile clean` target cleans the wrong directory.** It removes `./bpf/*.o` and
  `./bpf/*_bpf*.go`, but the actual bpf2go-generated artifacts live in
  `internal/collector/` (per the `//go:generate` directives there). `bpf/` only ever
  contains the `.bpf.c` sources and `vmlinux.h`. `make clean` never removes what it
  appears to intend to remove — masked because `go generate` unconditionally
  overwrites existing generated files anyway.
- **Pinned toolchain (`clang-14`, `llvm-strip-14`) declared but never wired in.** The
  `Makefile` sets `CLANG`/`LLVM_STRIP` variables that are never referenced by the
  `generate` target or by any `//go:generate` directive — bpf2go silently uses
  whatever `clang`/`llvm-strip` resolve to on `$PATH` instead, undermining the
  reproducibility the pinned versions are meant to guarantee.
- **`TcpCollector` and `BytesCollector` each load a full separate copy of the same BPF
  object.** Each independently loads `TcpMonitorObjects` and only attaches a subset of
  its programs, but each still causes the kernel to verify/relocate every program in
  `tcp_monitor.bpf.c` and allocates its own private `sock_to_pid` map — only the copy
  attached to the tracepoint (inside `TcpCollector`) is ever populated or read;
  `BytesCollector`'s copy is dead weight. Wasteful, not functionally incorrect (shared
  `tracked_pids` via `MapReplacements` is handled correctly).
- **`InstallExtractor` discards already-computed results on any parse error.** If
  `package.json` parses successfully but `package-lock.json` is malformed (or vice
  versa), the function returns a fully zeroed `InstallFeatures{}` rather than
  preserving whatever was already successfully extracted — inconsistent with how
  gracefully it handles *missing* files. Untested: `install_extractor_test.go` covers
  v1/v3/missing-file cases but no malformed-JSON case.
- **`isNpmInstallInvocation` uses an overly loose substring match** — it checks
  whether *any* argv token's basename contains `"npm"`, not just argv[0]/the binary
  name, so a command like `some-tool install --npm-mode` could spuriously satisfy it
  and create a bogus session.
- **`unregisterSession` does a full linear scan of `pidToSession`** under the
  exclusive write lock on every single session completion, blocking all concurrent
  routing across every other active session while it does so — O(N) in total tracked
  PIDs across all sessions rather than O(children of this session); the session
  already tracks its own PID set (`LivePIDs`), so a reverse index would avoid this.
- **No `-race`, no `test` target, no CI.** The `Makefile` has no `test` target at
  all, and no CI config exists in the repo, so none of the concurrency-sensitive
  tests (`TestRouter_RaceConditions`, `TestConcurrency`) are guaranteed to ever run
  under `go test -race` as part of normal workflow — meaning C2/C3 above would not be
  caught even by the tests that come closest to exercising them.
- **`test_tcp_direct.go`** is an ad-hoc manual-verification program (not a `_test.go`
  file, no `testing` import) sitting at the module root with no build tag excluding
  it from `go build ./...`/`go vet ./...`. It duplicates collector-wiring logic
  already in `cmd/monitor/main.go` with no shared code.

---

## Low

- `Makefile`'s `verify-toolchain` documents itself as requiring root but never
  actually checks the effective UID — running it unprivileged fails later with a
  cryptic bpftool/libbpf permission error instead of the documented message. It also
  silently assumes the checkout lives at exactly `~/capstone` (the `/capstone` suffix
  in `CAPSTONE_DIR`'s derivation is hardcoded even though the variable is
  override-able).
- `go.mod` pins `cilium/ebpf v0.13.0`, which is dated relative to current releases;
  worth a refresh for CO-RE/BTF compatibility fixes on newer kernels.
- `syscall_tracer.bpf.c` hardcodes two x86-64-specific syscall numbers as "noise"
  exclusions (correctly commented as arch-specific) — since every collector's
  `bpf2go` invocation targets `amd64` only, the project isn't actually
  architecture-portable despite the CO-RE narrative in the docs implying it is.
- `bpf/file_monitor.bpf.c`'s `contains_pattern` helper is defined but never called
  anywhere — dead code the BPF verifier still has to accept.
- Redundant nested locking: `Session.AddFile`/`AddBytes` take `session.mu` and then
  call into `FiletopAggregator` methods that *also* take their own internal mutex —
  harmless (no deadlock risk, consistent lock ordering) but inconsistent with
  `DirCounts`/`TCPAggregator`/`NGramCounter`, which rely solely on `session.mu`.
  Reinforces how easy it is to accidentally end up like C2 (BuildRecord bypassing
  `session.mu` entirely) when locking discipline isn't uniform across aggregators.
- `NGramCounter`'s sliding window grows via repeated `append`+reslice on a slice
  capacitated to 5, causing avoidable backing-array reallocation churn over ~13,000
  pushes per install; a fixed `[5]uint32` ring buffer would avoid it. No correctness
  bug — verified the cap-at-5 sliding-window logic is otherwise correct.
- `tcp_aggregator.go`'s IP byte-order conversion (`kernelBEU32ToIPv4`/`ntohl`) is
  functionally correct (verified against the actual `binary.LittleEndian` decode in
  `tcp_collector.go` and covered by `TestKernelBEU32ToIPv4`) but unnecessarily
  convoluted — a good candidate for a future accidental endianness bug if "simplified"
  without re-deriving the reasoning in its own doc comment.
- `internal/collector/tcp_collector.go` keeps a `TcpEvent = TCPEvent` compatibility
  alias with no remaining callers of the old name found — likely safe to remove.

---

## Test coverage gaps

| Area | Status |
|---|---|
| `syscall_collector.go`, `file_collector.go`, `tcp_collector.go`, `bytes_collector.go` | **No tests at all** (only `process_collector_test.go` has a struct-layout assertion) |
| `cmd/dataset/{exporter,labeler,validator}` | **Zero test files** — the mislabeling bug (C4) and the CSV/doc mismatch (H6) are both invisible to `go test ./...` |
| Session lifecycle (exec/fork/exit) | Tested, but mostly via the **dead** `Submit*`/`Detector.Run` path (H3), not the real `Router`→`Detector` production path |
| Timeout racing a near-simultaneous normal exit | **Not tested** (the exact scenario in C3) |
| Concurrent `BuildRecord` read vs. session writers | **Not tested** (the exact scenario in C2) |
| Cross-channel out-of-order event delivery | **Not tested** (H4) |
| Malformed (not just missing) `package.json`/`package-lock.json` | **Not tested** |
| PID reuse / stale session aliasing | **Not tested** (H7) |
| `-race` enforcement | **No Makefile/CI target runs it** |
| `internal/output/writer.go` | Untested (consistent with being dead code) |

---

## Repo hygiene

- **No `.gitignore` anywhere in `npm-ebpf-monitor`.**
- **Compiled binaries are committed to git**: `monitor`, `exporter`, `labeler`,
  `validator` (3-6 MB ELF executables each) are tracked, not merely present in the
  working tree.
- **bpf2go-generated artifacts are committed**: `internal/collector/*_x86_bpfel.go`
  *and* their paired `.o` binary blobs are both tracked. This is a defensible choice
  for building without a BPF toolchain present, but there is no CI check verifying
  the committed `.o` bytecode actually matches the current `.bpf.c` source, so they
  can silently drift if someone edits the C without re-running `go generate` before
  committing.
- **`coverage.out` is tracked** and, based on its contents, only ever covered the
  `internal/session` package — a stale artifact from one ad-hoc test run, not a
  full-repo coverage report.
- **`report/` (~13.7 MB of PDFs/docx) is currently untracked but unguarded** — with no
  `.gitignore` rule excluding it, a routine `git add -A`/`git add .` would sweep this
  large binary content straight into the source repo.
- A `.gitignore` covering `/monitor`, `/exporter`, `/labeler`, `/validator`, `*.o`,
  `coverage.out`, and `/report/` is overdue.

---

## Positive notes

- **Test fixtures (`tests/packages/*`) are well-designed and safe.** The six
  simulated benign/malicious `postinstall.js` scripts (crypto-miner, env-stealer,
  ci-secret-grabber, reverse-shell, suspicious, benign) each cite the real-world
  incident they model (event-stream, ua-parser-js, ctx package, flatmap-stream),
  document why they're safe, and hold to it: no destructive filesystem actions, no
  real credential values transmitted (only key *names*, values redacted), no actual
  reverse shell or miner executed. One caveat worth a one-line callout in test docs:
  `env-stealer-test`, `ci-secret-grabber-test`, `crypto-miner-test`, and
  `benign-test` all make *real* (not simulated) HTTP/HTTPS calls to the public
  `httpbin.org`, carrying hostname/platform/username — safe with respect to secrets,
  but real local info does leave the test machine on every run, and it's an external
  network dependency for otherwise-hermetic tests.
- The core architectural shape — CO-RE BPF probes sharing one `tracked_pids` map,
  ring-buffer transport, `bpf2go`-generated bindings, a single-writer session state
  machine, per-session mutexes, and a schema-validated JSON/CSV output contract — is
  a sound design that mostly matches its own documentation; the issues above are
  implementation gaps and a few doc/code mismatches, not a flawed architecture.
- No hardcoded secrets, tokens, or user-specific absolute paths were found anywhere
  in the Go source or shell scripts.

---

## Summary table

| Severity | Finding | Location |
|---|---|---|
| Critical | `write_processes`/`read_processes` always wrong (flags never captured) | `bpf/file_monitor.bpf.c:257`, `internal/features/filetop_aggregator.go` |
| Critical | `BuildRecord` reads session state with no locking | `internal/output/json_writer.go:114-146` |
| Critical | Session can be completed twice (timeout vs. exit race) | `internal/session/detector.go:292-320, 417-441` |
| Critical | Malicious test fixtures silently mislabeled benign in training CSV | `cmd/dataset/labeler/main.go`, `cmd/dataset/validator/main.go`, `internal/output/json_writer.go` |
| High | `d.timers` leaks an entry per timed-out session | `internal/session/detector.go:417-452` |
| High | `pending_opens` BPF map leaks on mid-syscall process kill | `bpf/file_monitor.bpf.c` |
| High | Dead `Detector.Run`/`Submit*` path; most of `detector_test.go` tests it, not prod code | `internal/session/detector.go`, `router.go`, `detector_test.go` |
| High | Router "priority" doesn't guarantee cross-stream ordering the docs claim | `internal/session/router.go` |
| High | Silent event drops under backpressure, never counted/logged | all 5 files in `internal/collector/` |
| High | `ml_handoff.md` CSV column table self-contradictory (code is correct) | `docs/ml_handoff.md:45-92` |
| High | PID-reuse aliasing risk if an EXIT event is dropped | `internal/session/detector.go` (`handleExec`) |
| Medium | Dead code: `output/writer.go`, `features/aggregator.go`, `collector/collector.go` | respective files |
| Medium | Stale binary name breaks `compare_packages*.sh` | `scripts/compare_packages.sh:14`, `compare_packages_multi.sh:14` |
| Medium | `make clean` cleans the wrong directory for generated artifacts | `Makefile` |
| Medium | Pinned clang/llvm-strip never actually wired into build | `Makefile` |
| Medium | `TcpCollector`/`BytesCollector` double-load the same BPF object | `internal/collector/{tcp,bytes}_collector.go` |
| Medium | `InstallExtractor` discards partial results on any parse error | `internal/features/install_extractor.go` |
| Medium | Loose `isNpmInstallInvocation` substring match | `internal/session/detector.go` |
| Medium | `unregisterSession` full-map scan under exclusive lock | `internal/session/detector.go` |
| Medium | No `-race`/`test` Makefile target/CI | `Makefile`, repo root |
| Medium | `test_tcp_direct.go` untagged debug script at module root | `test_tcp_direct.go` |
| Low | Various — see [Low](#low) section | — |
| Info | No `.gitignore`; binaries/`.o`/`coverage.out` tracked in git; `report/` unguarded | repo-wide |

---

## Addendum — post-audit updates

**C1 is fixed.** `bpf/file_monitor.bpf.c` now captures `openat`'s flags in the enter
probe and carries them to the exit probe through the existing `pending_opens` map.
Measured against a real `npm install`: 1,469 of 1,473 file events now carry real flags
(previously 0 of 1,473), and `write_processes` went from `0` to a correct non-zero
value. Work log, tests, rationale and raw evidence:
[`docs/fix-c1-open-flags/`](docs/fix-c1-open-flags/).

Note that the existing `sessions/*.json` corpus is **still affected** — those values
cannot be recovered by re-processing and must be re-captured.

**New Critical finding — ProcessTracer does not load on current kernels. FIXED.**
`bpf/vmlinux.h` is a stale dump that declares `trace_event_raw_sched_process_fork` with
`char parent_comm[16]` / `char child_comm[16]`. Upstream has since converted those to
`__string(...)`, so on current kernels they are `__data_loc` u32 descriptors. The
`ctx->child_comm` CO-RE relocation could not resolve, cilium/ebpf poisoned the
instruction with `0x0BAD2310`, and the verifier rejected
`tracepoint__sched__sched_process_fork` — **the `monitor` binary exited 1 on startup and
could not capture anything.** Fixed by reading the child's name with
`bpf_get_current_comm()` (the helper the sibling exec and exit handlers already use)
instead of from the tracepoint context. Work log, tests, rationale and evidence:
[`docs/fix-processtracer-fork-load/`](docs/fix-processtracer-fork-load/).

With the binary able to start, the C1 fix was confirmed end-to-end for the first time: a
real `npm install lodash` traced by the real monitor wrote a session reporting
`"write_processes": 1`, against `0` in all four pre-fix `lodash` sessions committed in
`sessions/`.

`bpf/vmlinux.h` remains stale — this program no longer depends on the part that
diverged, but any future access to a tracepoint field whose *kind* has changed will fail
the same way. Signature: `0xBAD2310` / `195896080`.

**New High finding — session files are silently lost when the package spec contains a
`/`. FIXED.** The parsed package name is interpolated straight into the output filename, so
`npm install ./localdep` produces the path `<out>/npm-<id>_./localdep.json` and `open`
fails with ENOENT. The error is logged and dropped: the session's data is discarded and
the exit status is unaffected, so a batch capture would lose every affected session
without any signal. Observed directly.

Fixed by sanitising each filename component in `JSONWriter.Write`: characters outside
`[A-Za-z0-9._@-]` collapse to `-`, and the result is trimmed so it can never be empty,
`.`, `..`, or a hidden file. The package name *inside* the record is untouched, and the
corpus package names — which the labeller matches on by substring (see C4) — are
byte-for-byte unchanged. Verified end to end: `npm install ./localdep` now writes
`npm-1787404508_localdep.json` containing `"package_name": "./localdep"`, where before it
wrote nothing at all. Details:
[`docs/fix-output-filename-sanitization/`](docs/fix-output-filename-sanitization/).

The *call site* has since been fixed too. `cmd/monitor/main.go` still continues past a
failed write — aborting a long capture over one bad write would discard the sessions
still to come — but it now counts the failures, reports them at shutdown
(`LOST n of m session(s)`), and exits non-zero, so any remaining cause of write failure
(full disk, read-only mount) is loud rather than silent. It also prints
`Wrote n session record(s).` on a clean run, so a capture can be checked against the
number of installs performed. Details:
[`docs/fix-silent-write-failures/`](docs/fix-silent-write-failures/).

**New Medium finding — the fork handler filters a thread id against a tgid-keyed map.
FIXED.** `sched_process_fork` reported `parent_pid` as the forking *task's* id, but
`tracked_pids` is keyed by tgid everywhere else in the codebase. For a multithreaded
process forking from a non-leader thread the lookup missed and the fork event — and
that child's whole subtree — was silently dropped: exactly the evasion a malicious
install script forking from a Node `worker_threads` worker would produce.

Fixed by resolving the tgid via `bpf_get_current_pid_tgid()` instead of
`ctx->parent_pid` — the same call every other consumer of `tracked_pids` already makes.
Demonstrated deterministically (previously "not demonstrated in production") with a
small C fixture that forks from a pthread guaranteed not to be the process's leader
thread, rather than relying on Go runtime scheduling luck. The pre-existing fork test's
own workaround for this exact bug — seeding every thread id instead of just the
tracked process's pid — was removed once it was no longer needed. Details:
[`docs/fix-fork-tgid-lookup/`](docs/fix-fork-tgid-lookup/).

One related concern surfaced but left unfixed: the *insert* side still writes
`child_pid` into `tracked_pids` unconditionally, which is correct for a genuine
`fork()` but writes a thread id (not a tgid) for a `CLONE_THREAD` event. Recorded as
Low in
[`docs/fix-fork-tgid-lookup/07-findings-not-fixed.md`](docs/fix-fork-tgid-lookup/07-findings-not-fixed.md).
