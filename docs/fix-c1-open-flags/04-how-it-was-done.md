# 4. How it was done

## 4.0 Method

The TDD skill at `skills/.agents/skills/tdd/` was followed. Its rules that shaped this
work:

- **Confirm the seams before writing tests.** Where a test observes behaviour is a
  design decision, agreed up front rather than discovered mid-implementation.
- **One test → one implementation change.** Vertical slices, not a batch of tests
  followed by a batch of code.
- **Red before green, always.** A test that has never failed has never been shown to
  test anything.
- **Test through public interfaces**, not internals; expected values are independent
  literals, not recomputations of the implementation.
- **Refactoring is not part of the loop.**

## 4.1 Choosing the seam — the decision that shaped everything

Before writing anything, one question had to be answered: **can any pure-Go test go red
on C1?**

The answer is no, and understanding why determined the whole approach.

`TestFiletopAggregatorParsesWriteFlags` already existed and already passed. It
constructs `FileEvent{Pid: 101, Flags: uint32(syscall.O_WRONLY)}` by hand and checks
the aggregator classifies it as a write — which it does, correctly. That test was
green throughout the entire lifetime of the bug. It was testing the aggregator against
flag values *that the real pipeline had never once produced*.

Any test that builds its own `FileEvent` inherits that blindness. The defect lives
strictly upstream of the aggregator, in the kernel. So the only seam that can observe
C1 is:

> load the real BPF program into the kernel, perform a real `openat(2)`, and read what
> comes back out of the ring buffer.

That requires root. This was raised and confirmed before any test was written, and
root access was arranged (passwordless `sudo` for `go`, via
`/etc/sudoers.d/99-ani-nopasswd`) rather than the seam being compromised to something
testable without it.

**This is the central lesson of the whole exercise.** The pre-existing test suite was
not merely missing a test — it contained a *green test that looked like coverage of the
broken behaviour* and was not. Choosing a seam that could not fail was how the bug
survived.

## 4.2 The slices

### Slice 1 — `O_RDWR` counts as both (pure Go)

Done first because it is independent of the kernel work and could be closed quickly.

1. Wrote `TestFiletopAggregatorCountsReadWriteOpensAsBoth`. Ran it. **Red:**
   `ReadProcesses = 0, want 1`.
2. Changed exactly one condition in `filetop_aggregator.go` — added
   `|| mode == syscall.O_RDWR` to the read branch.
3. Ran it. **Green.** Re-ran the four pre-existing filetop tests: all still pass, so
   the change did not alter `O_WRONLY`, `O_CREAT` or `O_RDONLY` behaviour.

### Slice 2 — the layout guard (not a slice, honestly)

Wrote `TestFileEventLayoutMatchesBPFStruct` against `unsafe.Sizeof` / `unsafe.Offsetof`
expecting it to reveal a layout mismatch. **It passed immediately.**

Under the TDD rules this does not count as a slice — nothing was driven by it. It was
kept as a regression guard and labelled as such. Its real value was diagnostic: it
proved the wire format was innocent, which eliminated "add a flags field to the
struct" as a candidate fix and pointed the investigation squarely at the producer.

### Slice 3 — flags reach userspace (kernel)

1. Wrote `TestFileCollectorReportsOpenFlagsFromRealOpenat`. Ran it as root against the
   then-current BPF object. **Red:** *"no O_WRONLY|O_CREAT file event observed for this
   process within 5s; open flags are not reaching userspace."* C1 confirmed against a
   live kernel, not merely by reading source.
2. Read `sys_exit_openat`'s context definition and confirmed the actual constraint:
   `struct trace_event_raw_sys_exit` carries only `id` and `ret`. The flags are simply
   not available at exit. This is *why* the original author wrote `evt->flags = 0` —
   it was not an oversight in the exit probe so much as a missing handoff from the
   enter probe.
3. Noticed that `dir_category` was already being ferried enter→exit through
   `pending_opens`. Added `flags` to the same struct, populated it from `ctx->args[2]`
   at enter, and read it at exit.
4. Regenerated the BPF object and re-ran. **Green** in 0.52s.

### Slice 4 — end-to-end against real `npm install`

Written last, once the mechanism was proven, to close Goal 3.

The double-aggregation control (feeding every event through a second aggregator with
`Flags` zeroed) was added deliberately so that the before/after comparison happens
**within a single run on a single event stream**. Comparing two separate npm runs would
have left open the possibility that the difference came from npm, the filesystem cache,
or timing rather than from the fix.

## 4.3 Regenerating the BPF object

`go generate ./internal/collector/` failed:

```
Error: exec: "llvm-strip": executable file not found in $PATH
```

clang 22.1.8 is installed but the LLVM binutils are not. GNU `strip -g` was verified to
remove DWARF while preserving the `.BTF` and `.BTF.ext` sections (matching the section
shape of the committed artifact), and generation was re-run with
`BPF2GO_STRIP=/usr/bin/strip`.

**This is a workaround, not a fix.** `llvm-strip` should be installed; see
[05-why-this-approach.md](05-why-this-approach.md#on-the-strip-workaround).

## 4.4 A wrong turn, and how it was undone

Worth recording, because the recovery is the useful part.

`go generate ./internal/collector/` regenerates **all four** BPF programs, not just the
one whose source changed. Immediately afterwards, the monitor binary failed to start:

```
load ProcessTracer: ... program tracepoint__sched__sched_process_fork:
load program: invalid argument: invalid func unknown#195896080
```

The obvious inference was that the regeneration — specifically the GNU `strip`
workaround — had corrupted the objects. Three of the four objects were restored from
git, leaving only the intentionally-changed `filemonitor` pair regenerated.

**The error persisted, identically.** The inference was wrong: the failure exists in
the committed object too, and predates this work entirely. Root cause is in
[07-out-of-scope-blocker.md](07-out-of-scope-blocker.md).

Two things were nevertheless kept from the false start:

- The three unrelated objects stayed restored. Regenerating them was never necessary,
  and leaving unnecessary binary churn in the diff would obscure the actual change.
- The restore was done with a targeted `git checkout --` on six specific paths, not a
  blanket revert. The working tree carries a large amount of pre-existing uncommitted
  work (see `git status`), and a broad revert would have destroyed it.

## 4.5 Verification performed

| Check | Command | Result |
|-------|---------|--------|
| Full suite, unprivileged, race detector | `go test -race ./... -count=1` | all `ok` |
| Full suite, as root | `sudo -n /usr/bin/go test ./... -count=1` | all `ok` |
| Build | `go build ./...` | clean |
| Vet | `go vet ./internal/features/` | clean |
| Formatting | `gofmt -l` | new files clean |
| Red reproduction, slice 1 | revert aggregator condition | fails as expected |
| Red reproduction, slice 3 | `git checkout` pre-fix `.o` | fails as expected |
| Red reproduction, e2e | `git checkout` pre-fix `.o` | fails as expected |

Raw output for all of these is in [`evidence/`](evidence/).
