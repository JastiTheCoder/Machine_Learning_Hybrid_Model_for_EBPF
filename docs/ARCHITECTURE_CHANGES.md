# Architecture — current state and what changed since the last audit

**Date:** 2026-08-25
**Companion to:** [`NEW_AUDIT.md`](NEW_AUDIT.md) (findings) — this document covers the
same window (`AUDIT.md`'s last commit, `16164fe`, 2026-08-22, through the current
working tree) from a design perspective: what the system looks like now, what moved,
and why each change is an improvement (or, in one case, a new architectural surface
worth watching).

**Relationship to existing architecture docs:** `context/architecture.md` and
`docs/misc/architecture_deep_dive.md` (identically duplicated at
`docs/ml_handoff.md`'s sibling, `docs/misc/`) already document the six-layer pipeline
in full depth, with code snippets and line-linked references. Both predate this
window and describe it accurately for everything they cover — this document does not
replace them, and neither should be reorganized or merged as a side effect of writing
this one (flagging the `ml_handoff.md` duplication specifically for a maintainer
decision, per [`NEW_AUDIT.md`](NEW_AUDIT.md)'s Medium findings, rather than acting on
it here). This document instead adds the layer those two do not cover at all — the
verdict scoring engine — and calls out what changed underneath the layers they do
cover.

---

## The shape that hasn't changed

`npm-ebpf-monitor` still traces one `npm install` through the same pipeline
`AUDIT.md` described and the existing architecture docs diagram in detail:

```
 kernel: 4 CO-RE eBPF programs (process_tracer, syscall_tracer, file_monitor, tcp_monitor)
    │  share one tracked_pids hash map, seeded by process_tracer
    ▼
 per-program ring buffers (BPF_MAP_TYPE_RINGBUF)
    ▼
 5 Go collector goroutines (process/syscall/file/tcp/bytes), bpf2go-generated bindings
    ▼
 1 router goroutine (single-consumer select over all 5 event channels)
    ▼
 Detector — one Session per npm root PID, keyed by pidToSession
    ▼
 Session — feature aggregators (FiletopAgg, DirCounts, TCPAgg, NGramCtr, Evidence)
    ▼
 BuildRecord — Snapshot() → SessionRecord (JSON) + CSV export
```

This shape is sound and was not touched by anything in this window. What changed is
(a) what flows through the file-event path, (b) what `Session` accumulates alongside
its existing counters, and (c) an entirely new stage after feature aggregation and
before output.

---

## 1. Kernel boundary: the opened path now survives the syscall

**Before:** `bpf/file_monitor.bpf.c`'s `sys_enter_openat` classified a path into a
`dir_category` byte and discarded the path itself; `sys_exit_openat` — which is where
the ring-buffer event is actually emitted, since only it knows whether the `open()`
succeeded — had no access to the path at all, because tracepoint exit contexts only
carry the return value. `FileEvent.Filename` existed as a field but was always
`memset` to zero.

**Now:** `struct pending_open` (the map-based handoff between the enter and exit
probes, already used to carry `dir_category` and, since `AUDIT.md`'s C1 fix, `flags`)
gained a `filename[256]` member. The enter probe reads the path into it directly
(deliberately *not* into a second stack scratch buffer first — the comment at
`file_monitor.bpf.c:242-246` notes this was necessary to stay under the BPF
verifier's 512-byte stack limit once the struct itself carries 256 bytes). The exit
probe `memcpy`s it straight into the emitted event.

**Why this is beneficial:** every path-based classification the new evidence layer
does (SSH keys, cloud credentials, `/etc/shadow`, cron/systemd drop-ins, shell rc
files — thirteen classes in `internal/features/pathclass.go`) is downstream of this
one field. Before this change, none of that was possible in userspace at all; the
kernel side was emitting directory-category-only telemetry with no way to
distinguish "opened something in `/etc/`" from "opened `/etc/shadow`" specifically.
This is the one kernel-side change the entire verdict-engine feature depends on.

**A second, independent bug this surfaced (not part of the same change, but found
while testing it):** `internal/collector/file_collector.go`'s `FileEvent` Go struct
was missing an explicit 4-byte padding field between `Flags` (`uint32`, ending at
byte 268) and `TimestampNs` (`uint64`, requiring 8-byte alignment, so the C compiler
places it at byte 272). `encoding/binary.Read` has no notion of either compiler's
struct-alignment rules and reads fields back-to-back by declared size, so it was
reading `TimestampNs` four bytes early — silently corrupting every `FileEvent
.TimestampNs` ever decoded, since the field was first written. This was invisible
until `EXFIL-001`'s ordering check became the first thing in the project to depend on
that field's numerical correctness. Fixed by adding `Pad2 [4]uint8` explicitly
(`file_collector.go:83`) so `binary.Read` consumes the real wire bytes instead of
misreading past them.

---

## 2. Collector layer: every drop is now visible

**Before:** all five collectors used the same silent-drop pattern under backpressure
(`select { case c.Events <- evt: default: /* drop */ }`) with no counter anywhere.

**Now:** each collector tracks a `dropCount` (`sync/atomic`) and exposes
`DroppedEvents()`; `cmd/monitor/main.go` reports every nonzero count at shutdown.
Separately, `Detector.RouteToSession` now counts drops caused by events arriving for
a PID with no registered session yet (`DroppedRoutesForUnknownPID`), and
`file_monitor.bpf.c` gained a `file_monitor_stats` BPF array map counting
`pending_opens` insert failures, read out via `PendingOpensInsertFailures()`.

**Why this is beneficial:** this is a monitoring tool whose entire value proposition
is complete, trustworthy telemetry per install. Before this change, a session with
undercounted features due to backpressure or an out-of-order EXEC event looked
identical, from the outside, to a session that genuinely had fewer of those things
happen. Now every layer that can silently lose data — the kernel-side bounded map,
the userspace channel buffers, and the router's PID-not-yet-registered gap — reports
a number an operator or a batch-capture script can check. It does not close any of
the underlying races (see `NEW_AUDIT.md`'s H4/H7 entries), but it converts "silent
and unverifiable" into "counted and reportable," which is most of what a monitoring
tool can promise short of eliminating the race outright.

---

## 3. Session lifecycle: one arbiter instead of two racing completions

**Before:** a session could be completed by the router goroutine (on the last live
PID's exit) or by a `time.AfterFunc` timeout callback on its own goroutine, with
nothing to stop both from winning — `AUDIT.md`'s C3, plus a compounding `d.timers`
leak (H1) when the timeout path never cleaned up its own entry.

**Now:** `Session.MarkCompleteOnce(timedOut bool) bool` (`session.go:352-363`) wraps
a `sync.Once`; both completion paths call it and only the one that returns `true`
proceeds to `unregisterSession` + send on `completedSessions`. Both paths also now
unconditionally call `stopSessionTimer` first, regardless of which one wins, closing
H1 as a side effect of the same fix.

**Why this is beneficial:** this is the textbook shape for "exactly one of two
racing goroutines should win" — a single, cheap, correctly-synchronized arbitration
point instead of two independent code paths each hoping the other doesn't also fire.
It is also exactly the kind of primitive the newer `EvidenceCollector` wiring
benefited from having already established (see §4) rather than needing to invent its
own.

Alongside this, `BuildRecord` no longer reads live `Session` fields directly — it
consumes `Session.Snapshot()` (`session.go:289-330`), which takes `s.mu` once and
returns cloned maps, closing `AUDIT.md`'s C2 (an unsynchronized concurrent read that
could crash the process with `fatal error: concurrent map read and map write`).
`Snapshot()` is also where the new `Evidence` field is folded in (see §4) — the
verdict engine's input is, by construction, exactly as consistent as every other
feature the session already produced.

Separately, the entire `Detector.Run()`/`SubmitProcess`/`SubmitSyscall`/`SubmitFile`/
`SubmitTCP` machinery — dead in production since before this window, per `AUDIT.md`'s
H3, but still exercised by most of `detector_test.go` — was removed. `Detector
.Shutdown(ctx)` replaces it: its only remaining job is closing `Completed()` on
context cancellation. Tests were migrated onto the real `Router`-driven path. This
does not change runtime behavior (the dead path was never called by `cmd/monitor`
either way) but it means the test suite now actually exercises the code path
production uses, which is a meaningful increase in how much a green `detector_test.go`
run is worth.

---

## 4. A new accumulator alongside the existing ones: `EvidenceCollector`

`Session` already accumulated `FiletopAgg`, `DirCounts`, `TCPAgg`, and `NGramCtr` —
each a bounded, purpose-built summary of one raw event stream. `Evidence
*features.EvidenceCollector` (`session.go:42`) is a fifth, added the same way and
governed by the same lock (`s.mu`) every other aggregator already uses — `AddPath`,
`AddProcess`, and `AddTCP`'s existing collector calls now also feed it
(`session.go:89, 126, 158`).

Unlike the numeric aggregators, `EvidenceCollector` retains *classified raw facts*,
not just counts:

- **`internal/features/pathclass.go`** classifies a file path into one of thirteen
  `PathClass` values (SSH keys, `.npmrc`, AWS/Docker/Kube credentials, `.gitconfig`,
  `/etc/passwd`/`/etc/shadow`, `.env`, crypto wallets, shell rc files, cron/systemd
  drop-ins) by suffix or substring match — no `$HOME` resolution needed, so it works
  under any username.
- **`internal/features/argvclass.go`** classifies a spawned process's `comm`/argv
  into one of five `ArgvClass` values (shell spawn, network tool, base64 decode,
  eval/exec, chmod+x) — token-based, not a raw substring search, so `curl` only
  matches as an actual binary name, never as a substring of some unrelated word.
- Both are small, closed enums, so — unlike the free-form `comms`/`endpoints` sets,
  which are capped at 32 distinct entries each with a `Truncated` flag when the cap
  is hit — the classified sets can never grow unbounded; there are only as many
  possible values as there are enum members.
- `EvidenceCollector` also tracks the earliest timestamp each of five `Indicator`
  values was observed (`FirstSeen`), which is what makes an *ordering* rule — "was a
  sensitive read seen before an outbound connection?" — possible downstream.

**Why this is beneficial:** the numeric aggregators can tell you *how much*
happened (611 temp-dir accesses, 3 TCP state transitions) but not *what* — the
project's own audit history (`AUDIT.md`'s positive notes) already observed the
attack-simulation fixtures were well-designed but had no mechanism translating "read
`.ssh/id_rsa`, then connected to `1.2.3.4:4444`" into a feature the pipeline could
act on. `EvidenceCollector` is that mechanism: it is what makes the new rule engine
(§5) possible without either reimplementing path/argv parsing per-rule or reaching
back into raw event structs after the fact.

---

## 5. A new stage entirely: the verdict scoring engine (`internal/verdict`)

This is the one addition in this window with no prior layer to extend — a new
package, evaluated once per completed session, that turns accumulated evidence into
an explainable decision.

```
Session.Snapshot()  →  verdict.Input  →  verdict.Evaluate(input, rules, thresholds)  →  verdict.Verdict
   (features.*)         (features.* types,        │                                      { Score, Level,
                          no session import)       ├─ 12 weighted rules fire/don't        Thresholds, Findings }
                                                    ├─ 2 of them Decisive
                                                    └─ Findings sorted (weight desc, ID asc)
```

- **`Rule`** (`verdict/rule.go`): `{ID, Weight, Decisive, Technique, Eval func(Input)
  (bool, string)}` — a MITRE ATT&CK technique reference travels with every rule, so a
  finding is self-explaining without a lookup table.
- **`Input`** (`verdict/rule.go:22-31`) is built entirely from `features.*` types,
  deliberately never importing `internal/session` — `session` hydrates evidence under
  its own lock, `internal/output` builds an `Input` from what `Snapshot()` already
  produced. This keeps the dependency graph acyclic (`verdict → features`, never
  `verdict → session`) and makes every rule testable with a hand-built `Input`, no
  collector, no root, no `Session` at all — which is exactly how all twelve rules'
  positive/near-miss test pairs in `verdict/rules_test.go` are written.
- **`Evaluate`** (`verdict/verdict.go:58-103`) sums fired rules' weights, bands the
  total against `Thresholds{Suspicious, Malicious}`, and forces `LevelMalicious`
  unconditionally if any `Decisive` rule fired — regardless of total score. Two rules
  are decisive: `PERSIST-001` (wrote into a cron/systemd/shell-rc-shaped location)
  and `EXFIL-001` (a sensitive read strictly before an outbound connect).
- **`Derived`** (`verdict/derived.go`) holds install-size-normalized ratios
  (`NetworkOpsRatio`, `ProcessOpsRatio`) so a rule stays portable across a
  1-dependency install and a 400-dependency one, rather than comparing raw counts
  that scale with install size.
- **`DefaultRules`** (`verdict/registry.go`) is the twelve-rule set this package
  ships, built through `MustRegister` — which panics at package `init` on a
  duplicate rule ID, catching a silent double-counting bug at the moment it would be
  introduced rather than as a later miscalibrated-score mystery.

Three of the twelve rules' thresholds were calibrated against real data, not guessed:
`CRED-001` explicitly excludes `.npmrc` after real captures of `lodash`/`express`/
`chalk`/`debug` showed a 100% false-positive rate against it; `PROC-003`'s
process-spawn-ratio baseline and `DROP-001`'s temp-directory-writer-count threshold
were similarly set from what those same captures showed versus the project's
malicious fixtures. **`NEW_AUDIT.md`'s NC1 finding is that this same calibration
exercise did not reach `EXFIL-001`**, because none of those four calibration
captures had a working TCP capture in this environment — the gap is in one rule's
input signal, not in the decisive-rule mechanism or the rest of the registry.

**Why this is beneficial, net of NC1:** the project previously had no synthesis step
at all between "here are 36 numeric features" and "is this malicious" — that
judgment lived entirely in the (out-of-scope, ML-team-owned) Random Forest model
downstream, with no fast, explainable, dependency-free pre-screen available in the
collection tool itself. `internal/verdict` is exactly that: a human can read a
`Finding`'s `RuleID`, `Technique`, and `Evidence` string and understand *why* a
session was flagged without touching the ML pipeline at all, and
`TestBuildRecordFeatureFieldsUnaffectedByVerdict` (`internal/output/verdict_output_test.go`)
proves the 36 QUT-DV25 fields the ML team's contract depends on are byte-for-byte
unaffected by any of it — the new stage is strictly additive to what already existed.

---

## 6. Output contract: additive, not breaking

`SessionRecord` gained one field, `Verdict *verdict.Verdict`
(`internal/output/json_writer.go:40`), and `CurrentSchemaVersion` moved `1.0.0` →
`1.1.0`. `ToCSVRow`'s 39-column export is untouched — the verdict block is
JSON-only. A `1.0.0` reader that ignores unknown JSON keys still works against a
`1.1.0` file; a `1.0.0` file with no `"verdict"` key still unmarshals (`Verdict`
stays `nil`). `cmd/monitor` prints a live `[ALERT]` line to stdout
(`printMaliciousAlert`, `main.go:396-399`) for any session whose verdict bands
malicious, and gained `-suspicious-threshold`/`-malicious-threshold` flags so an
operator can retune banding without a rebuild.

**Why this is beneficial:** additive schema evolution is the right call for a
project whose downstream consumer (the ML pipeline) is explicitly out of this
engineer's scope to modify — a breaking schema change would have forced a
coordination point this project's own `CLAUDE.md` says not to create. The live
`[ALERT]` line is the first operator-facing signal this tool has produced at all
during a capture; previously the only way to know a session was concerning was to
open its JSON file after the fact.

---

## 7. Ground truth: grew a real-world benign cohort

`internal/dataset/labels.go`'s `fixtureLabels` table (itself a fix from *before* this
window, closing `AUDIT.md`'s C4) gained four entries: `lodash`, `express`, `chalk`,
`debug` — real, unmodified npm-registry packages, category `benign-real-world`. This
is what made the calibration in §5 possible at all: without a benign sample that
wasn't one of the project's own six hand-written fixtures, there was no way to
distinguish "this rule fires on real ordinary installs" (bad) from "this rule only
fires on our own malicious simulations" (the point) until real packages were added to
compare against.

---

## Net assessment

Every change in this window either closes a gap `AUDIT.md` already named (C1–C4,
H1–H3, H5) or adds a genuinely new capability (path/argv evidence, the verdict
engine, real-world ground truth) on top of infrastructure (`Snapshot()`,
`MarkCompleteOnce`) that was itself hardened during the same window. The one place
this audit found the new layer's own reasoning to have a gap — `EXFIL-001`'s shared,
unfiltered use of `IndicatorSensitiveRead` — is narrow, identified, and directly
fixable without touching the decisive-rule mechanism, the evidence-collection
design, or anything in layers 1–4 above. See `NEW_AUDIT.md` for that finding and the
rest of this window's open items in full.
