# 5. Why this approach

## Why keep going after a failed write

The instinct on finding a swallowed error is to stop swallowing it — fail fast,
abort the run. That is wrong here.

The monitor's job is a long, mostly unattended capture. If session 3 of 40 fails
to write and the monitor exits, sessions 4 through 40 are never collected: a
partial loss becomes a total one, and the operator has to start over. Continuing
costs one session; aborting costs the rest of the run.

So the `continue` stays, and the change is about *visibility* instead. Every
failure is counted, the count is reported, and the exit status reflects it. The
operator learns exactly as much as they would from a hard failure, and keeps the
37 sessions that worked.

This is also why the test asserts `failed == 3` rather than `failed >= 1` — that
exact count is what proves the worker did not quietly become fail-fast.

## Why exit non-zero at all, if the run continues

Because the consumer of a capture run is usually a script, and a script cannot
read log lines. Goal 3 exists so that `./capture.sh && ./train.sh` does the right
thing: an incomplete corpus stops the pipeline instead of silently training a
model on missing data.

The two mechanisms are complementary, not redundant — the log line tells a human
*which* sessions were lost, the exit status tells a script *that* something was.

## Why `exitCodeForOutput` is its own function

`main` loads BPF and calls `os.Exit`, so it cannot be unit-tested. Anything left
inside it is verified only by reading. Extracting the decision leaves a pure
function with four table-driven cases, and shrinks the untestable remainder to a
single call — `os.Exit(exitCodeForOutput(outStats))` — whose correctness is
obvious by inspection.

The function is thin. Thinness is not the point; testability at the boundary is.

## Why the parameter was narrowed to a channel

The worker took a `*session.Detector` and used one method on it. Testing it in
that shape would have meant building a detector and driving synthetic exec/exit
events through it to produce a completed session — a large amount of unrelated
machinery, and a test whose failures could come from the detector rather than
the worker.

Taking `<-chan *session.Session` makes the dependency match the actual use, and
the test helper becomes three lines. This is a narrowing, not a rewrite: the
call site changes from `detector` to `detector.Completed()`.

The distinction matters because the `tdd` discipline treats refactoring as
outside the red-green loop. This was decided during "confirm the seam", before
any test was written, precisely so it was not a change made to chase a green.

## Why not a mock writer

`runOutputWorker` takes a concrete `*output.JSONWriter`. Mocking would have meant
introducing an interface for the test's benefit, and the test would then prove
the worker counts failures *of a mock* — saying nothing about how the real
writer fails.

Pointing the real writer at a real bad path exercises the real `os.MkdirAll` and
the real `ENOTDIR`. Nothing is faked, and no production type changed shape to
accommodate a test.

This is the same reasoning that drove the [C1 open-flags
fix](../fix-c1-open-flags/) to reject a userspace test in favour of a live
kernel: test where the truth is. There, the truth was in the kernel. Here it is
in the filesystem, and `t.TempDir()` provides a real one.

## Why the permissions-based failing writer was rejected

`os.Chmod(dir, 0o555)` is the textbook way to make a write fail, and it would
have been a latent trap in this repository. The suite is run under `sudo` so the
eBPF tests can load, and root ignores directory permissions — under root the
writer would succeed and `all writes fail` would go red for a reason unrelated to
anything the change touches.

The failure would have been noticed, since the root suite is part of the
verification. But it would have cost real time to diagnose, and a test that
inverts its own result depending on how it is invoked is a bad test even when
it happens to be caught. `ENOTDIR` holds for every user.

## Why the success count prints unconditionally

Goal 2 is that an operator can compare "wrote N session record(s)" against the
number of installs they ran. A count printed only under `-verbose` does not
achieve that, because the operator has to already suspect a problem to enable it
— and the entire failure mode being fixed is one where nobody suspects anything.
