# 1. Goals

## The defect

Recorded as the **High** finding in the addendum to [`../../AUDIT.md`](../../AUDIT.md).

`internal/output/json_writer.go` built the output path like this:

```go
path := filepath.Join(w.outputDir, fmt.Sprintf("%s_%s.json", record.SessionID, record.PackageName))
if err := os.WriteFile(path, payload, 0o644); err != nil {
    return "", err
}
```

`record.PackageName` is whatever argument npm was invoked with. It is not
validated anywhere upstream, and npm accepts a wide range of specs:

| Spec form | Example |
|---|---|
| registry name | `lodash` |
| local path | `./local-dep`, `../shared/pkg` |
| scoped name | `@scope/pkg` |
| file URL | `file:../thing` |
| git URL | `git+https://host/x.git` |
| tarball path | `./suspicious-test-1.0.0.tgz` |

Every form after the first contains `/`. Interpolated into a filename, the `/`
is read as a directory separator, so `os.WriteFile` tries to create
`<out>/npm-1787403056_./localdep.json` — a file inside a `<out>/npm-1787403056_.`
directory that does not exist. The write fails with `ENOENT`.

## Why it was silent

`cmd/monitor/main.go:290-295`:

```go
path, err := writer.Write(record)
if err != nil {
    log.Printf("write session %s: %v", completed.ID, err)
    continue
}
```

The error is logged and the loop moves on. Nothing retries, nothing exits
non-zero, nothing marks the session as failed. A capture run over a corpus of
packages could lose an arbitrary subset of its sessions and still look like it
succeeded — the operator would only notice by counting output files.

This was not hypothetical. It was hit for real during the previous task, while
running the npm end-to-end test:

```
write session npm-1787403056: open <out>/npm-1787403056_./localdep.json: no such file or directory
```

At the time it was worked around by switching the fixture to `npm install
lodash`. That workaround is what this task removes.

## The second, worse case

A spec beginning `../` produces a path that is *valid* rather than failing:
`filepath.Join(outputDir, "npm-x_../escapee.json")` cleans to a file one level
**above** the output directory. That write succeeds, so the failure is even
quieter — the file exists, just not where anything will look for it, and it may
overwrite something that is not ours.

## Goals

1. **A session must never be lost because of its package name.** Any spec npm
   accepts must produce a written, readable session file.
2. **The file must land inside the configured output directory.** No spec may
   cause a write above it.
3. **The recorded data must not change.** Sanitisation applies to the filename
   only; `package_name` inside the JSON must still be exactly what npm was
   invoked with, because that is the ground truth for the dataset.
4. **Existing filenames must not change.** The corpus package names, and the
   substring matching the dataset labeller relies on, must be byte-for-byte
   preserved.
5. **Prove it against the real binary**, not just at the unit seam — the same
   `npm install ./localdep` that failed before must now produce a session file.

## How we would know

- Goal 1, 2, 3 → a table-driven test over awkward specs asserting the write
  succeeds, `filepath.Dir(path)` equals the output directory, and the
  round-tripped `package_name` matches the input verbatim.
- Goal 4 → a regression guard pinning the exact filename for each package name
  the project actually captures.
- Goal 5 → run the real monitor, run the real `npm install ./localdep`, and read
  the session file off disk.
