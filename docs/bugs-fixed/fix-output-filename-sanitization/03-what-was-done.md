# 3. What was done

Two files changed. No BPF code, no regeneration, no kernel involvement — this
defect is entirely in userspace Go.

## `internal/output/json_writer.go`

### Change 1 — the write site

```diff
-	path := filepath.Join(w.outputDir, fmt.Sprintf("%s_%s.json", record.SessionID, record.PackageName))
+	filename := fmt.Sprintf("%s_%s.json", sanitizeFilenamePart(record.SessionID), sanitizeFilenamePart(record.PackageName))
+	path := filepath.Join(w.outputDir, filename)
```

`record.SessionID` is sanitised as well. It is generated internally as
`npm-<unix-timestamp>` and is safe today, but sanitising both parts makes the
guarantee unconditional: *the result of `Write` is always a plain file directly
inside `outputDir`*, regardless of what either field contains. That is an
invariant worth being able to state without a caveat, and it costs one call.

### Change 2 — the sanitiser

Added at the end of the file, with `strings` added to the imports:

```go
// maxFilenamePart caps each component of a session filename. Most filesystems
// limit a single name to 255 bytes; two capped parts plus the separator and the
// ".json" suffix stay comfortably inside that.
const maxFilenamePart = 100

func sanitizeFilenamePart(part string) string {
	var b strings.Builder
	b.Grow(len(part))

	for _, r := range part {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '_' || r == '@' || r == '-':
			b.WriteRune(r)
		default:
			// Collapse a run of unsafe characters into a single separator.
			if !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}

	safe := strings.Trim(b.String(), ".-")
	if len(safe) > maxFilenamePart {
		safe = strings.Trim(safe[:maxFilenamePart], ".-")
	}
	if safe == "" {
		return "unnamed"
	}
	return safe
}
```

Four rules, in order:

1. **Allowlist.** `[A-Za-z0-9._@-]` passes through; everything else becomes `-`.
   An allowlist rather than a denylist, so a character nobody thought of is safe
   by default rather than dangerous by default.
2. **Collapse.** A run of unsafe characters becomes one `-`, so `://` does not
   become `---`.
3. **Trim, then cap, then trim again.** Trimming `.` and `-` from both ends
   removes the leading `..` of a traversal, prevents hidden files, and rules out
   the reserved names `.` and `..`. The second trim matters because truncation
   can expose a fresh trailing separator.
4. **Fallback.** If nothing survives, `"unnamed"`.

The full mapping it produces is recorded in
[`evidence/sanitizer-mapping.txt`](evidence/sanitizer-mapping.txt):

```
"lodash"                        -> "lodash"
"suspicious-test-1.0.0.tgz"     -> "suspicious-test-1.0.0.tgz"
"@scope/pkg"                    -> "@scope-pkg"
"./localdep"                    -> "localdep"
"../escapee"                    -> "escapee"
"./a/b/c"                       -> "a-b-c"
"file:../thing"                 -> "file-..-thing"
"git+https://example.com/x.git" -> "git-https-example.com-x.git"
".."                            -> "unnamed"
""                              -> "unnamed"
"/etc/passwd"                   -> "etc-passwd"
```

One line there deserves a note rather than a silent pass: `file:../thing`
becomes `file-..-thing`, which still contains `..`. That is intentional and
safe. `..` is only meaningful as a *whole path component*, bounded by
separators; with every `/` removed there can be no such boundary, so the result
is an ordinary filename with two dots in the middle of it. Stripping interior
dots would have cost the readability of names like `lodash-4.17.21` for no gain.

## `internal/output/json_writer_test.go`

Added `strings` to the imports and appended the two tests described in
[02-tests.md](02-tests.md). No existing test was modified.

## What was deliberately not changed

`cmd/monitor/main.go` still logs and continues when `Write` fails. That is a
real weakness, but it is a *separate* one, and it is now much harder to trigger.
It is written up in [07-findings-not-fixed.md](07-findings-not-fixed.md) rather
than folded into this change.
