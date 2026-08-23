# 5. Why this approach

## Why real compiled binaries, not a reimplementation of `main()`

The whole point of this task is to validate what an operator actually runs.
A test that reimplements `cmd/monitor/main.go`'s wiring inline (as the
`internal/session`/`internal/collector` unit tests reasonably do, to keep
each seam narrow) would only prove that *the reimplementation* behaves
correctly — it would silently stop testing anything the moment `main.go`
itself drifted from what the test assumed. Building the real binary with
`go build` and driving it as a subprocess, the same way
`scripts/compare_packages*.sh` and a real operator would, is the only way to
make "the overall execution of the program" mean what it says.

## Why synthetic local fixtures, not `tests/packages/*`'s real attack simulations

`tests/packages/` already contains real, safe attack-simulation fixtures
(`crypto-miner-test`, `reverse-shell-test`, etc.) with genuine network calls,
timeouts up to 8 seconds, and `spawnSync` recon commands. They are the right
tool for validating *detection fidelity* — whether the pipeline notices
attacker-shaped behavior — which is not this task's question. This task
needs the pipeline's *plumbing* (capture, propagation, labeling,
shutdown, exit status) to be exercised quickly and deterministically,
independent of network reachability in whatever environment the suite runs
in. Synthetic fixtures named after the same table entries
(`internal/dataset/labels.go`) give C4's labeling test everything it needs
(a name the ground-truth table recognizes) without any of the network
dependency or multi-second runtime the real fixtures carry. This mirrors
`internal/features/filetop_npm_e2e_test.go`'s own `newNpmFixture`, which
made exactly this choice for the same reason when validating C1.

## Why the `process_tree` assertion doesn't fully close fork-tgid-lookup's item B

That fix's own `07-findings-not-fixed.md` names the gap precisely: its fix
was proven against a synthetic C fixture forking from a genuinely
non-leader pthread, not against "a real `npm install` running a real
install script that uses Node's `worker_threads` module." This task's
`process_tree` assertion proves real npm, real node, and the real kernel
tracepoints propagate a child process correctly end to end — a strictly
stronger real-world signal than the C fixture alone — but Node's own
postinstall child, spawned via ordinary `child_process`, almost certainly
forks from its main OS thread, so it does not exercise the specific
tid-vs-tgid mismatch that fix corrected. Closing that fix's item B fully
would need a fixture whose postinstall script deliberately uses
`worker_threads` to fork a child from a non-main thread — a real fixture-
engineering effort, correctly identified by that fix's own document as
"substantially larger and less certain" than the C-fixture approach it
already took, and not something a plumbing-focused regression suite should
take on as a side effect. Recorded honestly in
[07-findings-not-fixed.md](07-findings-not-fixed.md) rather than claimed as
closed.

## Why the router flake was fixed in the test, not in `Router.Run`

`Router.Run`'s dispatch loop is correct: it receives an event and processes
it synchronously, in order, before looping back to select again — there is
no reordering, no drop, and no race in the production code. The race is
entirely in how the *test* observed completion: an unbuffered channel send
returning tells you the value was handed off, not that the receiving
goroutine has finished acting on it. Changing `Router.Run` itself (for
instance, adding an acknowledgment channel back to the sender) would add
production-only-for-tests machinery to the hottest path in the event
pipeline, to fix a bug that does not exist there. The correct fix is the one
already used one test above it in the same file
(`TestRouter_Multiplexing`'s own `waitForCondition` call) — wait for the
externally-observable effect (the counter reaching its expected value) with
a bounded poll, exactly this project's established idiom for exactly this
class of "the goroutine that should have finished by now, might not have
yet" problem.

## Why the four Step-3 reds were investigated, not just patched blind

Per the TDD skill and this project's own "checked for teeth" culture (see
the H4 and H5 fixes' own honesty about negative results and discovered
bugs), a red that appears while writing a *new* test must be sorted into
"a real bug this test correctly caught" or "a flaw in the test itself"
before doing anything about it — patching either kind blind risks either
masking a real defect or building a test that no longer tests what it
claims to. Each of the four reds in Step 3 was traced to its exact
mechanism (the struct's byte budget, npm's own documented config system,
argv ordering, the monitor's own documented whole-machine scope) via
independent reading and, for the npm-specific one, independent manual
reproduction outside the failing test — the same discipline that let this
task correctly distinguish those four (test-only) from the fifth,
`TestRouter_UnknownPID` (a genuine, pre-existing bug), rather than treating
all five reds identically.
