# Planned fixes — pre-implementation briefs for `NEW_AUDIT.md`'s Critical/High findings

This directory is a new sibling to `docs/bugs-fixed/`, `docs/new-features/`, and
`docs/misc/` — not one of the three categories `CLAUDE.md` names, because those
three are for *finished* work. This one is for work that hasn't started: a
self-contained brief per finding, written before any code changes, so each can be
handed to its own isolated agent session (this project's established convention —
see any `docs/bugs-fixed/<name>/` directory) without that session needing to
re-derive the genesis, the options, or the test strategy from scratch.

**Source:** [`../NEW_AUDIT.md`](../NEW_AUDIT.md) (findings) and
[`../ARCHITECTURE_CHANGES.md`](../ARCHITECTURE_CHANGES.md) (design context), both
dated 2026-08-25. Scope is the six Critical/High findings from that audit;
Medium-severity code findings are out of scope for this batch (left for a future
round). Three repo-hygiene items that aren't code bugs get lighter single-file
cleanup plans instead of the full bug-plan/test-plan pair.

## Convention

Each bug gets a directory with two files:

- **`01-bug.md`** — three sections: **How it came about** (the specific commit
  that introduced the bug and why, traced via `git log`/`git blame`, not
  guessed), **Candidate fixes** (two or more named, concrete plans, each with
  what it changes, what it costs or risks, and which is recommended and why),
  and **Expected result** (an observable, falsifiable statement of what "fixed"
  looks like — a number or a pass/fail condition, the same bar
  `docs/bugs-fixed/*/06-results.md` already holds itself to).
- **`02-test-plan.md`** — follows `skills/.agents/skills/tdd/` directly:
  proposed seams to confirm before any test is written, then one vertical slice
  per behavior (never "write all the tests, then all the code"), and an explicit
  teeth-check plan for anything timing- or race-shaped, per this project's own
  `CLAUDE.md`: *"a test that merely exercises the code path is not sufficient...
  the test must reliably reproduce the vulnerable condition."* Where a bug has
  more than one candidate fix, the seams and the must-pass/must-still-pass
  assertions are written to test the observable contract, not one
  implementation, so the same test plan applies whichever candidate is chosen —
  only per-candidate notes call out where a specific plan needs its own extra
  unit-level seam.

Once a bug is actually fixed, its content should migrate into a new
`docs/bugs-fixed/<name>/` directory (following that directory's existing
`01-goals.md` … `07-findings-not-fixed.md` + `evidence/` structure, same as every
prior fix in this repo), and its `docs/planned-fixes/<name>/` directory should be
deleted — this directory is a staging area, not a permanent record.

## Index

| ID | Directory | Severity | One line |
|---|---|---|---|
| NC1 | [`nc1-exfil-decisive-false-positive/`](nc1-exfil-decisive-false-positive/) | Critical | Decisive `EXFIL-001` rule can band an ordinary `npm install` malicious on nothing but its own `.npmrc` read + registry connect |
| NC2 | [`nc2-labeler-test-corpus-pollution/`](nc2-labeler-test-corpus-pollution/) | Critical | `go test ./...` fails whenever the live `sessions/` directory contains a capture the labeler test doesn't know about |
| NH1 | [`nh1-evidence-truncated-not-surfaced/`](nh1-evidence-truncated-not-surfaced/) | High | `Evidence.Truncated` is computed but never reaches the persisted JSON or the verdict |
| H4 | [`h4-router-cross-channel-ordering/`](h4-router-cross-channel-ordering/) | High | Router's `procCh`-priority `select` narrows, but does not close, a cross-channel event-drop race |
| H6 | [`h6-ml-handoff-csv-table-mismatch/`](h6-ml-handoff-csv-table-mismatch/) | High | `docs/ml_handoff.md`'s CSV column table is self-contradictory, and now duplicated in two files |
| H7 | [`h7-pidtosession-pid-reuse-aliasing/`](h7-pidtosession-pid-reuse-aliasing/) | High | `pidToSession` has no generation guard against OS PID reuse aliasing one session's events onto another |

## Cleanup tasks (no TDD test suite — git/file operations, not testable code behavior)

| Directory | One line |
|---|---|
| [`cleanup-tasks/01-tracked-binaries-and-gitignore.md`](cleanup-tasks/01-tracked-binaries-and-gitignore.md) | Two full compiled binaries + `coverage.out` tracked in git, no `.gitignore` anywhere |
| [`cleanup-tasks/02-duplicate-ml-handoff-doc.md`](cleanup-tasks/02-duplicate-ml-handoff-doc.md) | `docs/ml_handoff.md` and `docs/misc/ml_handoff.md` are byte-identical duplicates |
