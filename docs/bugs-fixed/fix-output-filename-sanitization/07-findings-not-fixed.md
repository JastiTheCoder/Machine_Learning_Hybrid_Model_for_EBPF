# 7. Findings not fixed

Two things surfaced during this work and were deliberately left alone. Both are
recorded here rather than folded into the change.

---

## A. `cmd/monitor` swallows session write errors — Medium — **FIXED, see [`../fix-silent-write-failures/`](../fix-silent-write-failures/)**

`cmd/monitor/main.go:290-295`:

```go
path, err := writer.Write(record)
if err != nil {
    log.Printf("write session %s: %v", completed.ID, err)
    continue
}
```

A failed write is logged and forgotten. The monitor keeps running, exits zero,
and reports nothing at the end. This is *why* the filename bug was silent rather
than obvious, and it is the reason it survived long enough to reach an audit.

The filename fix removes the most likely cause of a write failure, but not the
category. A full disk, a permissions problem, or a read-only output directory
would still lose sessions the same quiet way — and a capture run is exactly the
situation where a disk fills up.

**Why not fixed here:** it is a behavioural decision about what the monitor
should do mid-run when persistence fails, with a real trade-off (aborting a long
capture on one bad write may be worse than continuing). It deserves its own
consideration, not a smuggled-in change behind a filename fix.

**Suggested shape:** count write failures and report the total on shutdown, and
exit non-zero if any occurred. That preserves the current "keep going" behaviour
while making the loss impossible to miss.

**Outcome:** fixed in the next task, in exactly that shape — see
[`../fix-silent-write-failures/`](../fix-silent-write-failures/).

---

## B. Sanitised names can collide — Low

The mapping is many-to-one. `./localdep` and `../localdep` and `localdep` all
produce `localdep`. Two different specs installed in two different sessions
therefore produce the same *package* component of the filename.

In practice this does not currently cause loss, because the filename is
`<session_id>_<package>.json` and `session_id` is `npm-<unix-timestamp>`, which
differs per session. Collisions would require two sessions in the same second.

**Why not fixed here:** the guarantee that actually matters — no session is
lost — already holds via the session ID, and the obvious remedy (appending a
hash of the original name) would break goal 4 by changing the filenames of
ordinary packages, which the labeller depends on.

**Worth revisiting if** the filename scheme ever drops the session ID, or if
sessions ever become sub-second.

---

## Still open from earlier work

Carried forward, unchanged, from
[`../fix-processtracer-fork-load/07-findings-not-fixed.md`](../fix-processtracer-fork-load/07-findings-not-fixed.md):

- **`bpf/vmlinux.h` is stale** relative to the running kernel. The ProcessTracer
  fix worked around one consequence; the underlying staleness remains and can
  poison other CO-RE relocations. Regenerating it requires `bpftool`.
- **The fork handler filters a TID against a TGID-keyed map**
  (`bpf/process_tracer.bpf.c`). Threads of a tracked process may not match. This
  was recorded as Medium in `AUDIT.md` but deliberately not over-claimed: the
  bare `process_tree` seen in the lodash sessions is *correct* for a package with
  no install scripts, so it is not evidence of the bug.
- **`llvm-strip` is not installed**, so `go generate ./internal/collector/...`
  fails. The workaround is `BPF2GO_STRIP=/usr/bin/strip`. This is a workaround,
  not a fix.
