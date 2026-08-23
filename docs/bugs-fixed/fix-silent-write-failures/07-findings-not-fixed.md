# 7. Findings not fixed

## A. The process exit status was not verified end to end — this environment

The decision is unit-tested and the wiring is recorded in
[`evidence/wiring.txt`](evidence/wiring.txt), but the monitor was never actually
started, made to fail a write, signalled, and observed exiting `1`.

**Why not:** the monitor needs root for BPF, and the sudo grant in this
environment covers only the `go` binary. A root-owned monitor process cannot be
signalled from this session, so `SIGINT` — the only path to the shutdown block —
is unreachable here.

**How to close it**, in two terminals:

```bash
# terminal 1 — output dir whose parent is a regular file, so every write fails
printf x > /tmp/blocker
sudo go run ./cmd/monitor -output-dir /tmp/blocker/sessions -verbose

# terminal 2
cd /tmp && npm install lodash --no-audit --no-fund
# back to terminal 1: Ctrl-C, then
echo $?     # expect 1, and a "LOST 1 of 1 session(s)" line
```

The clean-run half is confirmed by the same procedure with a real directory:
expect `Wrote 1 session record(s).` and `echo $?` → `0`.

This is a gap in *verification*, not a known defect — but it is the one claim in
[06-results.md](06-results.md) that rests on reading rather than running, so it
is named here rather than left implicit.

## B. Only the write step is counted — Low

`runOutputWorker` also calls `loadInstallFeatures`, which logs and continues on
error:

```go
installFeatures, err := loadInstallFeatures(completed)
if err != nil {
    log.Printf("extract install features for session %s: %v", completed.ID, err)
}
```

A session whose `package-lock.json` is unreadable is still written, but with
zeroed install features — so it lands in the corpus as a *degraded* record rather
than a lost one, and nothing in the new counts distinguishes it.

**Why not fixed:** it is a different category. Goals 1-4 are about sessions that
vanish; this is about sessions that arrive incomplete. Folding it into
`outputStats.failed` would conflate the two and make the exit status fire on
something that is often legitimate — a session with no `cwd`, or an install that
produced no lock file, is normal.

**Suggested shape:** a third counter, `degraded`, reported at shutdown but not
affecting the exit status.

## C. The count is not persisted — Low

The counts exist only in the shutdown output. A capture script that loses the
monitor's stdout has only the exit status.

**Why not fixed:** the exit status covers the scripted case, which is the one
goal 3 was written for, and adding a manifest file is a new output artifact with
its own format questions. Worth doing if the corpus capture ever needs a machine-
readable record of what a run produced.

---

## Still open from earlier work

Carried forward unchanged:

- **`bpf/vmlinux.h` is stale** relative to the running kernel. The
  [ProcessTracer fix](../fix-processtracer-fork-load/) worked around one
  consequence; the underlying staleness can poison other CO-RE relocations.
  Regenerating needs `bpftool`.
- **The fork handler filters a TID against a TGID-keyed map**
  (`bpf/process_tracer.bpf.c`) — Medium in `AUDIT.md`, deliberately not
  over-claimed: the bare `process_tree` in the lodash sessions is *correct* for a
  package with no install scripts, so it is not evidence of the bug.
- **`llvm-strip` is not installed**, so `go generate ./internal/collector/...`
  fails; the workaround is `BPF2GO_STRIP=/usr/bin/strip`. A workaround, not a fix.
- **Sanitised filenames can collide** — see
  [`../fix-output-filename-sanitization/07-findings-not-fixed.md`](../fix-output-filename-sanitization/07-findings-not-fixed.md).
  Harmless while filenames carry a per-session ID.
