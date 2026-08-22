# 5. Why this approach

## Why a `Snapshot()` method rather than exporting the lock

The smaller diff was to change `mu` to an `RWMutex` and give `Session` exported
`RLock`/`RUnlock`, then wrap `BuildRecord`'s existing body. It was rejected.

Exporting a lock makes correctness a property of *every caller, forever*. C2
exists precisely because one reader forgot; making the lock public means the
next reader can forget too, and the failure mode is an unrecoverable crash
rather than a compile error. A method that cannot be called incorrectly is
strictly better than a lock that must be remembered.

Keeping `mu` unexported also keeps the concurrency reasoning inside one package.
Today `internal/output` is the only outside reader; if a future dashboard or
in-kernel gate wants session state, it gets `Snapshot()` and cannot get it wrong.

## Why not just give the three aggregators their own mutexes

This was the third option, and it is the one that *looks* like the tidiest fix —
make `DirCounts`, `TCPAggregator` and `NGramCounter` self-protecting, matching
`FiletopAggregator`. It fails on two counts:

1. **It does not fix the bug.** `BuildRecord` also reads `sess.SyscallCounts`
   (a map, on `Session` itself) and `sess.ProcessTree` (a string being appended
   to). Neither lives in an aggregator. The crash vector the race detector
   actually reported first was `AddSyscall` vs `buildSyscallFeatures` — squarely
   outside any aggregator.
2. **It produces an inconsistent record.** Four independent locks means four
   independent instants. The filetop counts could come from before a burst of
   activity and the TCP counts from after it, yielding a feature vector that
   never described any real moment of the install. For a project whose entire
   output is feature vectors for a classifier, that is a quiet correctness bug
   traded for a loud one.

One lock, one instant, one coherent record.

## Why `maps.Clone` on `SyscallCounts` specifically

Each of the four aggregator read methods was checked rather than assumed:
`TCPAggregator.Counts()`, `DirCounts.ToMap()` and `NGramCounter.Snapshot()`
already build and return fresh values, so handing them out is safe.
`SyscallCounts` is the exception — it is the live map itself.

Returning it directly would have left the crash fully intact while *looking*
fixed: the lock would be released the instant `Snapshot` returned, and the
caller would then range over a map that collectors are still writing. The
independence test in slice 1 is what pins this.

## Why the race detector is the only acceptable oracle

A data race cannot be demonstrated by reading code or by a passing plain
`go test` — an unsynchronised read usually *works*, which is exactly why C2
survived to an audit. `go test -race` instruments memory access and reports the
conflicting pair with both stack traces, which is why this document can point at

```
runtime.mapassign_faststr()  session.(*Session).AddSyscall()
runtime.mapaccess1_faststr() output.buildSyscallFeatures()
```

and call it the crash vector rather than merely asserting one exists.

## Why the failed seam was kept and relabelled rather than deleted

The end-to-end Detector test does not reproduce C2 — proven by reverting the fix
and watching it still pass. Two honest options remained: delete it, or keep it
with the truth attached.

It was kept because it does something no other test does: drives a record from
raw collector events, through session creation, routing, completion and the
`Completed()` channel, to a finished `SessionRecord`. That is real coverage of
real wiring.

What would have been dishonest is leaving its original comment, which claimed it
"reproduces the production interleaving described in AUDIT.md C2". A future
reader trusting that claim would believe C2 had regression coverage it does not
have, and might delete slice 2 as redundant. The comment now states the negative
result and names slice 2 as the test with teeth.

## Why the teeth check was run at all

Slice 3 passed on the first run. The tempting reading is "the fix works,
end-to-end confirmed" — and that reading would have been wrong.

A guard's value is entirely in its ability to fail. Reverting the fix and
re-running cost about two minutes and converted an assumption into a measured
fact — one that changed what this documentation claims. It is the same
discipline applied in [`../fix-c4-ground-truth-labels/`](../fix-c4-ground-truth-labels/),
where the pre-fix labeller was reimplemented so the headline number could be
re-derived rather than quoted.
