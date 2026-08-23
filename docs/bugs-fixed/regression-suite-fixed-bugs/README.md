# Regression suite for every fix in `docs/bugs-fixed/` — and one flake it found

This directory documents one piece of work, different in shape from every
fix before it: not repairing one `AUDIT.md` finding, but building a
whole-program regression suite that formally re-validates **every fix
already shipped** in `docs/bugs-fixed/`, plus the sub-bugs those fixes
themselves discovered along the way — and fixing the one thing that suite's
own construction found broken.

Read the documents in order — they follow the sequence the work happened in.

| # | Document | Question it answers |
|---|----------|---------------------|
| 1 | [01-goals.md](01-goals.md) | What were we trying to achieve, and how would we know we had? |
| 2 | [02-tests.md](02-tests.md) | What tests were written, and were the goals achieved? |
| 3 | [03-what-was-done.md](03-what-was-done.md) | What was actually changed? |
| 4 | [04-how-it-was-done.md](04-how-it-was-done.md) | Step by step, including the flake this work found and closed. |
| 5 | [05-why-this-approach.md](05-why-this-approach.md) | Why whole-binary tests, and why fix the test instead of the code? |
| 6 | [06-results.md](06-results.md) | What are the final, measured results? |
| — | [07-findings-not-fixed.md](07-findings-not-fixed.md) | A fresh audit-wide re-check, done as part of this sweep. |
| — | [evidence/](evidence/) | Raw, unedited output for every claim made above. |

## One-paragraph summary

Every fix from C1 through H5 shipped with its own tests, each pinned at that
fix's own narrow seam (a single collector, a single BPF map, a single
detector method). None of them exercised the actual compiled `monitor`
binary end to end, and none of them re-validated a fix that a *later* fix's
own investigation happened to touch (e.g. the fork-tgid-lookup fix's own
`07-findings-not-fixed.md` names a real production gap — no npm+node
worker-thread scenario had ever driven it — that no unit test closes). This
task adds `cmd/monitor/e2e_regression_test.go`: three tests that build and
run the real `monitor` and `labeler` binaries against real (synthetic,
network-free) npm installs, chaining together C1's file-open flags,
processtracer-fork-load's kernel load fix, fork-tgid-lookup's propagation
fix, output-filename-sanitization, C4's ground-truth labeling, H3's
`Detector.Shutdown` wiring, and silent-write-failures' exit-status
reporting — in one real, running program, not five isolated unit seams.

Running that suite alongside the *entire* existing test suite — not in
isolation, per this project's own established "the whole suite is the real
bar" discipline (see the H5 fix's own `ProcessCollector` deadlock discovery)
— surfaced a second, real, pre-existing bug: `TestRouter_UnknownPID` (the H4
fix's own regression test) was flaky, failing 4 of 5 standalone runs, from a
synchronization gap between "a sender's channel send returned" and "the
router actually finished processing what it received." Fixed by giving that
test the exact same `waitForCondition` poll its sibling
`TestRouter_Multiplexing` already used for the identical reason — the
author had already solved this once in the same file, just not for this
test. Verified closed: 15/15 clean re-runs, and 3 further full-suite root
runs with zero failures anywhere.

## What shipped

- `cmd/monitor/e2e_regression_test.go` — three new tests driving the real
  compiled `monitor` and `labeler` binaries against real npm installs of
  synthetic local fixtures.
- One real bug fix: `internal/session/router_test.go`'s
  `TestRouter_UnknownPID` now polls for its drop counter to settle before
  asserting on it, closing a genuine, reproducible flake.
- Nothing in production code changed. This task is regression coverage and
  one test-only fix, not a new `AUDIT.md` finding's remediation.
