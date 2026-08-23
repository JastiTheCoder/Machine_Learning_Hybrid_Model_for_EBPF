# 5. Why this approach

## Why sanitise rather than reject

The alternative was to validate the package name and refuse to write when it
looks path-like. That is strictly worse for this project. The whole point of the
monitor is to capture data about installs, including installs of local tarballs
and directories — which is exactly how the malicious test fixtures
(`suspicious-test-1.0.0.tgz` and friends) are installed. Rejecting path-like
specs would refuse to record the most interesting sessions in the corpus.

Sanitising keeps every session. The filename becomes a display detail; the
authoritative package name lives inside the record, where nothing constrains it.

## Why an allowlist rather than a denylist

A denylist (`strings.ReplaceAll(name, "/", "-")`) fixes the case that was
observed and nothing else. It leaves `\` on other platforms, leading `.`,
control characters, NUL, and the length limit. An allowlist inverts the default:
anything not explicitly known to be safe becomes `-`. The failure mode of a
too-strict allowlist is an ugly filename; the failure mode of an
insufficiently-broad denylist is the bug recurring in a new form.

The set `[A-Za-z0-9._@-]` was chosen to cover real npm names exactly: `@` and
`/` for scopes (the `@` survives, the `/` collapses), `.` and `-` for versioned
tarballs, `_` because npm permits it.

## Why sanitising the filename but not the record

These are two different kinds of string. The filename is an *identifier* the
filesystem must accept and the labeller must be able to match. The
`package_name` field is *data* — the ground truth for what was installed, which
feeds a dataset used to train a classifier. Corrupting data to make a filename
legal would trade a loud, obvious bug for a quiet one in the training set.

So the transformation is applied at the boundary where the constraint actually
exists, and nowhere else. The test asserts this directly by reading the file
back and comparing `package_name` to the original spec.

## Why the backward-compatibility guard was written before the fix

This change alters an output format that something downstream parses. Per the
**C4** finding in `AUDIT.md`, the dataset labeller derives ground-truth labels
from substrings of the filename. A sanitiser that renamed
`suspicious-test-1.0.0.tgz` would not crash anything — it would silently produce
mislabelled training data, which is the worst class of bug this project can have.

Writing the guard *first*, and confirming it green against the original code, is
what makes it meaningful. Written afterwards it could only ever describe the new
behaviour.

## Why the slice test asserts properties, not exact filenames

Covered in [04-how-it-was-done.md](04-how-it-was-done.md) step 3. In short: for
the awkward inputs, nobody has an opinion about the exact output string — the
requirements are "it writes", "it stays inside the directory", "the data
survives". Asserting an exact filename there would encode an arbitrary choice as
a requirement and make the test break on harmless refactors. For the corpus
names the exact string *is* the requirement, so that test asserts it exactly.
Different requirements, different assertions.

## Why a unit seam here, when the last two fixes demanded a live kernel

The C1 open-flags fix explicitly rejected a userspace test, because the defect
was in the BPF producer and a hand-built `FileEvent` would have passed
throughout the bug's entire lifetime — as the pre-existing
`TestFiletopAggregatorParsesWriteFlags` in fact did. The seam had to be the real
kernel because that was the only place the truth lived.

The reasoning is the same here and lands somewhere different. The defect is in a
Go function that formats a string and calls `os.WriteFile`. `t.TempDir()` gives
a real filesystem, so the test exercises the real `ENOENT` and the real
`ENAMETOOLONG` — there is nothing faked, and no part of the failure requires a
kernel probe. The principle is "test where the truth is", not "always test at
the highest level".

The end-to-end run is still included, because the *call site* swallows errors
and only a real run proves the session survives the whole pipeline.

## Why `SessionID` is sanitised too

It is safe today (`npm-<unix-timestamp>`, generated internally). Sanitising it
anyway turns a conditional guarantee into an unconditional one: `Write` always
returns a plain file directly inside `outputDir`. That is a property worth being
able to state flatly — and it costs one function call on a path that runs once
per install.

## Why `cmd/monitor/main.go` was left alone

Making the monitor fail loudly on a write error is a genuine improvement, and it
is listed in [07-findings-not-fixed.md](07-findings-not-fixed.md). It is not
part of this change because it is a different decision with a different blast
radius: it changes what the monitor does during a long capture run when
something goes wrong, and it deserves its own consideration rather than being
smuggled in behind a filename fix.
