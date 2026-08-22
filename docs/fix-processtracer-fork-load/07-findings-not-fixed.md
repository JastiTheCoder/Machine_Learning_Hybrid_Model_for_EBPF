# 7. Findings discovered but not fixed

Two defects surfaced while validating this fix. Both are real and pre-existing; neither
is related to the ProcessTracer load failure. Recorded here so they can be picked up
deliberately rather than bundled into an unrelated change.

---

## Finding 1 — session files are silently lost when the package spec contains `/`

**Severity: High.** Observed directly, not inferred.

The first end-to-end attempt used `npm install ./localdep`. The monitor detected the
session, tracked it, completed it — and then failed to write it:

```
write session npm-1787403056: open <out>/npm-1787403056_./localdep.json:
  no such file or directory
```

The parsed package name (`./localdep`) is interpolated straight into the output
filename. The embedded `/` makes the kernel interpret it as a path into a `localdep`
subdirectory that does not exist, so `open` fails.

**Why it matters.** The failure is logged and then dropped — the run continues, the
session's data is discarded, and the exit status is unaffected. A batch capture would
lose every affected session silently. This is exactly the shape of bug that corrupts a
dataset without anyone noticing.

Any path-like or scoped spec triggers it: `./local-pkg`, `../pkg`,
`file:../thing`, and plausibly scoped names like `@scope/pkg`.

**Confirmed benign for the common case:** re-running with `npm install lodash` wrote
`npm-1787403111_lodash.json` correctly.

**Suggested fix.** Sanitise the package name before building the filename — replace
path separators, or use `filepath.Base`, or slugify to `[A-Za-z0-9._-]`. Additionally,
a failed session write should be surfaced more loudly than a log line, given the tool's
purpose is dataset collection.

**Note the interaction with an existing audit finding.** `AUDIT.md` records that
`labelFor` in the labeler keys off substrings of the *filename*. A sanitiser that
rewrites names must not change the substrings that labelling depends on.

---

## Finding 2 — `is_tracked(parent_pid)` compares a thread id against a tgid-keyed map

**Severity: Medium.** Found by reading the kernel's tracepoint definition while writing
Test 2. Worked around in the test; not demonstrated to bite in production.

The fork handler filters on:

```c
if (!is_tracked(parent_pid))
    return 0;
```

where `parent_pid` comes from the tracepoint's `TP_fast_assign`:

```c
__entry->parent_pid = parent->pid;   /* thread id */
```

`parent->pid` is the forking **task's** id — a tid. But `tracked_pids` is keyed by
**tgid**: the exec handler inserts `tgid`, and the exit handler's own comment states
*"tracked_pids stores tgids, not individual thread ids"*.

For a single-threaded process tid == tgid and the lookup works. For a multithreaded
process forking from any thread other than the group leader, the lookup misses and
**the fork event is silently dropped** — that child, and its entire subtree, never
joins the session.

**How it showed up.** Test 2 seeded only the test process's pid and was unreliable. It
now seeds every tid in `/proc/self/task`, which makes it deterministic. That workaround
is a symptom of the mismatch, not a fix for it.

**Not demonstrated in production, deliberately not over-claimed.** Every committed
session shows `process_tree: "npm(<pid>)"` with no children, which *looks* like
corroboration — but it is not evidence. The post-fix `npm install lodash` run produces
the same bare tree, and that is correct: `lodash` has no install scripts, so npm spawns
no subprocesses. Whether node spawns from its main thread (in which case this never
bites) was not determined.

**How to settle it.** Trace an install of a package that *does* run a postinstall script
— `tests/packages/benign-test` exists for this — and check whether the child node
process appears in `process_tree`. If it does not, this is the reason.

**Suggested fix.** Resolve the tid to its tgid before the lookup, rather than trusting
the tracepoint field:

```c
__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
if (!is_tracked(tgid))
    return 0;
```

This is valid here for the same reason the comm fix is: the tracepoint fires with
`current` == the forking task, so `bpf_get_current_pid_tgid() >> 32` is the parent's
tgid regardless of which thread forked. It also drops another dependency on a
tracepoint context field.

**Why it was not fixed here.** It is a behavioural change to which processes get
tracked, in a handler this change was already touching — bundling them would make both
harder to review, and this one deserves its own before/after evidence on a package that
actually forks.
