# 3. What was done

## `bpf/file_monitor.bpf.c` — the one kernel-side change

`struct pending_open` gained a `filename[FILENAME_LEN]` field; the enter
probe now reads the path directly into it (instead of a separate stack
buffer, since a second 256-byte scratch buffer on top of `pending_open`'s own
copy pushed this probe's stack frame over the verifier's 512-byte limit); the
exit probe's unconditional `memset` was replaced with a `memcpy` from
`po->filename`.

```c
 struct pending_open {
     __u32 flags;          /* openat() flags captured at enter time */
     __u8  dir_category;
     __u8  pad[3];
+    char  filename[FILENAME_LEN]; /* path captured at enter time, carried
+                                    * through to the exit probe's emitted
+                                    * event */
 };
```

```c
-    /* We don't have the filename here, so zero it out.  The consumer
-     * can correlate with pid + timestamp if needed. */
-    __builtin_memset(evt->filename, 0, sizeof(evt->filename));
+    /* The filename was captured at enter time (this probe's own context
+     * only carries the return value) and carried through pending_open. */
+    __builtin_memcpy(evt->filename, po->filename, sizeof(evt->filename));
```

`pending_opens` grows from ~12 B to ~268 B per entry (4096 entries max ≈
1.1 MB of kernel hash-map memory, up from ~48 KB — noted, not treated as a
concern; see [07-findings-not-fixed.md](07-findings-not-fixed.md)). The wire
`file_event` struct, `FileEvent`, and the JSON schema are all unchanged: the
256-byte `Filename` field already existed on the wire, unfilled.

`internal/collector/filemonitor_x86_bpfel.{go,o}` were regenerated
(`go generate ./...`); the other three BPF programs' compiled objects were
verified byte-identical to `HEAD`.

## `internal/collector/file_collector.go` — a second, independent fix

`FileEvent` gained an explicit `Pad2 [4]uint8` field between `Flags` and
`TimestampNs`:

```go
 type FileEvent struct {
 	Pid         uint32
 	Filename    [256]byte
 	DirCategory uint8
 	OpenSuccess uint8
 	Pad         [2]uint8
 	Flags       uint32
+	Pad2        [4]uint8
 	TimestampNs uint64
 }
```

This is not related to the `struct pending_open` change above — it is a
pre-existing bug in `FileEvent`'s Go definition, present since the wire
struct was first written, that this work's own end-to-end test happened to
be the first thing in the project to depend on `FileEvent.TimestampNs` being
correct. See [02-tests.md](02-tests.md)'s Stage 9 narrative for how it was
found, and [07-findings-not-fixed.md](07-findings-not-fixed.md) for why
fixing it here (rather than filing it as a separate, deferred item) was the
right call.

`internal/collector/file_collector_test.go` gained one new decode-level test,
`TestFileEventBinaryReadDecodesTimestampFromRealWireBytes`, and one new
assertion in the existing `TestFileEventLayoutMatchesBPFStruct` (the `Pad2`
offset). Neither requires root.

## `internal/features/{pathclass,argvclass,evidence}.go` — new files

- `pathclass.go`: `ClassifyPath(path string) PathClass`. Thirteen classes,
  matched by suffix (`/.ssh/id_rsa`, `/.npmrc`, `/.aws/credentials`, `/etc/passwd`,
  `/etc/shadow`, `/.docker/config.json`, `/.kube/config`, `/.env`, shell rc
  files, `/etc/crontab`, `/wallet.dat`) or substring for directory-identified
  classes (`cron.d/`, `systemd/system/`, `.electrum/`). No `$HOME`
  resolution needed.
- `argvclass.go`: `ClassifyArgv(comm, argv string) ArgvClass`. Five classes —
  shell spawn, network tool, base64 decode, eval/exec, chmod+x.
- `evidence.go`: `EvidenceCollector`, mutated under the caller's lock (no
  lock of its own, mirroring `DirCounts`/`TCPAggregator`). `AddPath`,
  `AddProcess`, `AddEndpoint` classify and record; `firstSeen
  map[Indicator]uint64` tracks the *earliest* timestamp per indicator via
  `markFirstSeen`, since events can arrive out of timestamp order (five
  independent ring-buffer readers feed one session, `AUDIT.md` H4).
  `Snapshot()` returns a deep-cloned, sorted `Evidence` value type; a
  32-entry cap on unbounded facts (comms, endpoints) sets `Truncated` rather
  than growing without bound.

## `internal/session/session.go` — evidence hydration

`Session` gained an `Evidence *features.EvidenceCollector` field.
`AddProcess`/`AddFile`/`AddTCP` each nil-guard-initialize it and feed it
under the method's existing `s.mu` lock:

```go
s.Evidence.AddProcess(comm, decodeArgs(event.Args), event.TimestampNs)
s.Evidence.AddPath(decodeFilename(event.Filename), event.Flags, event.TimestampNs)
s.Evidence.AddEndpoint(features.FormatEndpoint(event.Daddr, event.Dport), isRoot, event.TimestampNs)
```

`isRoot := event.Pid == s.NpmPID`. `Snapshot()` gained an `Evidence
features.Evidence` field, hydrated inside the same single `s.mu` acquisition
every other aggregator's snapshot already uses — no second locking scheme.

## `internal/verdict/` — new package

- `verdict.go`: `Level`, `Finding`, `Thresholds`, `Verdict`, `Evaluate`.
  `DefaultThresholds = {Suspicious: 25, Malicious: 60}`.
- `rule.go`: `Rule{ID, Weight, Decisive, Technique, Eval}`, `Input` (built
  from `features.*` types, never from `session.Session`, keeping the
  dependency graph `verdict → features` only).
- `registry.go`: `MustRegister` (panics on duplicate rule ID at init);
  `DefaultRules`, twelve rules.
- `derived.go`: `Derived{NetworkOpsRatio, ProcessOpsRatio}` — install-size-
  normalized, zero (not NaN/Inf) when their denominator is zero.
- `rules.go`: the twelve rules themselves — `EXFIL-001` and `PERSIST-001`
  decisive (weight 50 each), the other ten additive (weight 10–25). Every
  data-derived threshold carries a comment citing the specific numbers that
  set it (Stage 8; see [02-tests.md](02-tests.md)).

## `internal/output/json_writer.go` — output surface

`SessionRecord` gained `Verdict *verdict.Verdict \`json:"verdict"\``.
`BuildRecord` now takes a `verdict.Thresholds` parameter, constructs a
`verdict.Input` from the session snapshot's aggregators plus its new
`Evidence` field, and evaluates it against `verdict.DefaultRules`.
`CurrentSchemaVersion` bumped `"1.0.0"` → `"1.1.0"` — additive, backward
compatible: a legacy file with no `verdict` key unmarshals with `Verdict ==
nil`.

## `cmd/monitor/main.go` — live alert + threshold flags

```go
suspiciousThreshold := flag.Int("suspicious-threshold", verdict.DefaultThresholds.Suspicious, ...)
maliciousThreshold  := flag.Int("malicious-threshold", verdict.DefaultThresholds.Malicious, ...)
```

`runOutputWorker` gained an `alert func(output.SessionRecord)` parameter — a
seam so tests capture alerts without touching the real process's stdout —
wired to `printMaliciousAlert`, which fires only when
`record.Verdict.Level == verdict.LevelMalicious`:

```go
if record.Verdict != nil && record.Verdict.Level == verdict.LevelMalicious && alert != nil {
    alert(record)
}
```

```
[ALERT] session npm-1787503916 (package "e2e-exfil-test-1.0.0.tgz") -> MALICIOUS (score 95): EXFIL-001, CRED-001, ...
```

## `internal/dataset/labels.go` — real-world ground truth

Four real, unmodified npm-registry packages declared as `benign-real-world`:

```go
"lodash":  {Label: 0, Category: "benign-real-world"},
"express": {Label: 0, Category: "benign-real-world"},
"chalk":   {Label: 0, Category: "benign-real-world"},
"debug":   {Label: 0, Category: "benign-real-world"},
```

Two downstream test files needed small, directly-entailed updates (see
[02-tests.md](02-tests.md), Stage 8): `internal/dataset/labels_test.go`'s
undeclared-package examples, and `cmd/dataset/labeler/main_test.go`'s
independent `expectedLabels` map.

## `cmd/monitor/e2e_regression_test.go` — new end-to-end test

`newMaliciousLocalPackage` (parallel to the existing `newLocalPackage`) and
`TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert`: a
synthetic postinstall script writes and reads a `.ssh/id_rsa`-suffixed file
under a fixture-private temp directory, then connects to a listener the test
itself starts on `127.0.0.1` — no network dependency, no dependency on any of
`tests/packages/*`'s existing attack-simulation fixtures. Asserts
`schema_version == "1.1.0"`, `verdict.level == "malicious"`, `EXFIL-001`
present in `verdict.findings`, and `[ALERT]`/`MALICIOUS` on the monitor's
captured stdout.

## Not changed

- The 36 QUT-DV25 feature fields and the 39-column CSV export
  (`internal/features/*.go` aside from the three new evidence files;
  `cmd/dataset/exporter`; `ToCSVRow`) — verified by
  `TestBuildRecordFeatureFieldsUnaffectedByVerdict`, a byte-for-byte diff of
  the feature subtree with and without a verdict present.
- `bpf/process_tracer.bpf.c`, `bpf/syscall_tracer.bpf.c`,
  `bpf/tcp_monitor.bpf.c` — untouched; their compiled objects verified
  byte-identical to `HEAD`.
- `cmd/dataset/labeler`, `cmd/dataset/validator`'s own logic (only the test
  file's ground-truth map changed, per above).
- Any other `AUDIT.md` item not already noted above as a direct, in-scope
  consequence of this work — see [07-findings-not-fixed.md](07-findings-not-fixed.md).
