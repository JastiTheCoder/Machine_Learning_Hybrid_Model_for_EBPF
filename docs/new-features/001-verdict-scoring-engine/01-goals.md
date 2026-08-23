# 1. Goals

## The gap

The approved plan, verbatim, on why the daemon needed this:

> `npm-ebpf-monitor` currently ends at *data collection*: four eBPF programs
> feed five Go collectors, a session state machine accumulates counters, and
> a 36-field QUT-DV25 feature vector is written as JSON for the ML team's
> Random Forest. Nothing in the daemon ever forms an **opinion** about
> whether the install it just watched was malicious.

Verified by reading, not assumed, before any code was written:

- `Session.AddProcess` (`internal/session/session.go`, pre-fix) kept only
  `Comm` from each `ProcessEvent`; the real `Args[256]` argv was decoded
  nowhere.
- `TCPAggregator` (`internal/features/tcp_aggregator.go`, pre-fix) kept only
  set *cardinalities* (`remote_ips`, `remote_ports`) — the real
  `Saddr`/`Daddr`/`Sport`/`Dport` on each `TCPEvent` was discarded after
  counting.
- `bpf/file_monitor.bpf.c:283-285` (pre-fix) called
  `__builtin_memset(evt->filename, 0, sizeof(evt->filename))`
  unconditionally in the exit probe — the 256-byte `filename` field already
  existed on the wire (`FileEvent.Filename`, offset 4) but was never filled,
  because `struct pending_open` (the enter-probe's transient state, keyed by
  `pid_tgid`) never carried the path across to the exit probe.
- The 36 published features barely separate the existing six-fixture corpus:
  `benign-test` vs. `env-stealer-test` — `io_ops` 2150/2177, `file_ops`
  2016/2051, `network_ops` 78/117, `remote_ips` 6/6, `process_ops` 39/39. Only
  `reverse-shell-test` stands out (`process_ops` 123). A scorer built only on
  the published features cannot separate this corpus.

Three consequences shaped every stage that followed: (1) the raw evidence to
build a scorer from was already arriving on every event and being thrown
away, so no new eBPF collection was needed for two of the three inputs; (2)
the third — file paths — required exactly one kernel-side change, carrying
`filename` through `struct pending_open`; (3) the corpus could not calibrate
anything as-is and needed both a recapture and new real-world data.

## Why this now

This is net-new functionality, not a fix for a specific `AUDIT.md` item —
`docs/new-features/` per `CLAUDE.md`'s own categorization rule. It was scoped
and approved as a nine-stage plan (`/home/ani/.claude/plans/the-goal-of-this-cozy-trinket.md`)
before any code was written, with every stage gated on the full repository
suite, unprivileged and under root.

## Goals

1. **Rich per-event evidence reaches the scoring boundary, not just counts.**
   Real file paths, real argv shapes, real endpoints and process identity —
   classified, bounded, and deduplicated — not thrown away after being
   folded into a cardinality.
2. **A weighted rule engine turns that evidence into an explainable verdict.**
   Every fired rule names itself, its weight, a MITRE ATT&CK technique
   reference, and a human-readable reason — never a bare score with no story
   behind it.
3. **Some signals are decisive, not merely additive.** A credential read
   immediately followed by an outbound connection, or a write into a
   persistence-shaped location, has no benign explanation for an npm install
   script; either should force `malicious` regardless of what else did or
   didn't fire.
4. **Weights and thresholds come from real data, not guesses.** The six
   hand-written fixtures alone cannot calibrate anything — `benign-test`
   itself makes a real network call in its own postinstall script — so real,
   unmodified registry packages are captured alongside them specifically to
   separate "this is unusual for *any* npm install" from "this is unusual
   for *our own fixtures*."
5. **The verdict rides the existing contracts, not a parallel one.** It is a
   `verdict` block in the same session JSON `output.JSONWriter` already
   writes, hydrated through the same `Session.Snapshot()` coherent-read lock
   evidence for the other aggregators already uses — not a second locking
   scheme, a second file, or a second CLI tool.
6. **The 36-field ML contract is untouched.** `ToCSVRow` and the 39-column
   CSV export are unaffected; the verdict is JSON-only, additive, and a
   `schema_version: "1.0.0"` file with no `verdict` key must still unmarshal.

## How we would know

- Goal 1 → `internal/features/evidence_test.go`: every declared `PathClass`
  and `ArgvClass` classifies correctly with a table-driven near-miss
  negative for each; caps and dedup hold under thousands of duplicate facts;
  `firstSeen` records the *earliest* timestamp per indicator even when
  events arrive out of order (five independent ring-buffer readers feed one
  session).
- Goal 2 → `internal/verdict/rules_test.go`: every rule gets a positive and a
  near-miss negative case; `Evaluate`'s `Findings` carry rule ID, weight,
  technique, and evidence text for every fired rule.
- Goal 3 → `TestEvaluateDecisiveRuleAloneForcesMaliciousBelowThreshold`; for
  `EXFIL-001` specifically, ordering is forced in both directions —
  read-then-connect fires, connect-then-read does not, either fact alone
  does not.
- Goal 4 → a corpus-driven calibration pass (Stage 8) that reads captured
  sessions, scores every record, and checks the result against
  `internal/dataset`'s ground truth for both the original fixtures and four
  newly captured real packages; every threshold in `internal/verdict/rules.go`
  carries a comment citing the specific data that set it.
- Goal 5 → `session.Snapshot()`'s existing single-lock-acquisition contract,
  confirmed unchanged by re-reading its diff; a race test (`-race`, ≥1000
  iterations) covering concurrent `AddFile`/`AddProcess`/`AddTCP` against a
  concurrent `Snapshot()` loop.
- Goal 6 → `TestBuildRecordFeatureFieldsUnaffectedByVerdict` (marshal both a
  pre- and post-verdict record for the same session, diff the feature
  subtrees byte-for-byte) and a round-trip test that a real `schema_version:
  "1.0.0"` corpus file still unmarshals with `Verdict == nil`.

## eBPF/kernel-specific test notes

Two kernel-boundary changes shipped in this work, and each needed a
different kind of proof:

- **`struct pending_open` filename plumbing** (Stage 1, `bpf/file_monitor.bpf.c`):
  requires an actual load and run against the real kernel (root/`CAP_BPF`),
  not verifier/compile-level acceptance alone — the claim is about the
  *contents* of a live ring-buffer event after a real tracked `openat()`, and
  no static or mocked check can substitute for that.
  `TestFileCollectorReportsFilenameFromRealOpenat` (`internal/collector`) is
  root-gated and asserts the decoded `FileEvent.Filename` on a real event.
- **`FileEvent.TimestampNs` alignment fix** (Stage 9, discovered while
  building the new end-to-end test, `internal/collector/file_collector.go`):
  this one is a pure userspace decode bug and is fully provable at the
  decode/compile level — `TestFileEventBinaryReadDecodesTimestampFromRealWireBytes`
  builds a raw byte buffer matching the real 280-byte wire layout and asserts
  `binary.Read` recovers the timestamp from its true offset, with no root
  required. The root-gated end-to-end test additionally proves it against a
  real kernel event, since it is exactly what made
  `TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert`'s
  decisive `EXFIL-001` assertion fail before the fix.

No new kernel-version constraint beyond what this project already requires
(CO-RE/BTF support, already exercised by every other root-gated test in
`internal/collector`).
