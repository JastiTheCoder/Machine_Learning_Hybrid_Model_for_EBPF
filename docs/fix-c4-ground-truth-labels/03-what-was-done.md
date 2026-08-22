# 3. What was done

One new package, four modified files, three new test files.

## New: `internal/dataset/labels.go`

The single source of ground truth.

```go
type FixtureLabel struct {
	Label    int    // 0 = benign, 1 = malicious
	Category string // descriptive; the classifier trains on Label
}

var fixtureLabels = map[string]FixtureLabel{
	"benign-test":            {Label: 0, Category: "benign"},
	"suspicious-test":        {Label: 1, Category: "generic-suspicious"},
	"crypto-miner-test":      {Label: 1, Category: "cryptomining"},
	"env-stealer-test":       {Label: 1, Category: "credential-theft"},
	"ci-secret-grabber-test": {Label: 1, Category: "credential-theft"},
	"reverse-shell-test":     {Label: 1, Category: "remote-access"},
}

var ErrUnknownPackage = errors.New("package has no declared ground-truth label")

func Lookup(packageSpec string) (FixtureLabel, error)
```

Three properties matter:

- **Keys are base names.** `fixtureKey` strips a trailing `.tgz` and a trailing
  dotted-numeric version segment, so `crypto-miner-test-1.0.0.tgz` and
  `crypto-miner-test-2.1.0.tgz` both resolve to `crypto-miner-test`. The version
  check is strict (`isVersion` requires digits-and-dots plus at least one dot),
  so a genuinely hyphenated name is not truncated.
- **Lookup refuses rather than defaults.** An absent key is
  `ErrUnknownPackage`, wrapped with the spec, the resolved key, and the file to
  edit. The returned `FixtureLabel` is the zero value, whose `Category` is `""`
  — deliberately *not* `"benign"`, so a caller that ignores the error still
  cannot read it as a benign sample.
- **Adding a fixture requires editing this table.** That is the safety property,
  not an inconvenience: a new package cannot reach the training set with an
  unexamined label.

## `cmd/dataset/labeler/main.go`

`labelFor` (the substring heuristic) is gone. `main` is now a thin wrapper over
a testable `labelDirectory(dir string) (summary, error)`:

```go
truth, err := dataset.Lookup(spec)
if err != nil {
    // Deliberately leave the file unlabelled rather than guessing. A wrong
    // label is worse than a missing one: it reaches the training set looking
    // like ground truth.
    log.Printf("UNLABELLED %s: %v", entry.Name(), err)
    sum.failed++
    continue
}
record["label"] = truth.Label
```

`main` exits non-zero when `sum.failed > 0`, with a message naming what to do.
Per-file failures do not abandon the run — the same "keep going, count, exit
loudly" shape as [`../fix-silent-write-failures/`](../fix-silent-write-failures/).

`packageSpecOf` prefers the record's own `package_name` and falls back to
parsing the filename, so a record missing that field is still resolvable.

## `cmd/dataset/validator/main.go`

`derivedLabel` no longer reimplements the heuristic:

```go
func derivedLabel(filename string, rec output.SessionRecord) (int, error) {
	if rec.Label != nil {
		return *rec.Label, nil   // the labeler is the authority
	}
	...
	truth, err := dataset.Lookup(spec)
	if err != nil {
		return 0, err
	}
	return truth.Label, nil
}
```

A new **Rule 4** reports every session with no resolvable label and fails the
validation run, joining rules 1–3 in the final gate.

## `internal/output/json_writer.go`

```diff
-func (s *SessionRecord) ToCSVRow() []string {
-	labelStr := "0"
-	if s.Label != nil {
-		labelStr = strconv.Itoa(*s.Label)
-	}
+func (s *SessionRecord) ToCSVRow() ([]string, error) {
+	if s.Label == nil {
+		return nil, fmt.Errorf("session %q (package %q) has no label; run the labeler "+
+			"before exporting", s.SessionID, s.PackageName)
+	}
+	labelStr := strconv.Itoa(*s.Label)
```

`severity_score` mirrors `labelStr`, so refusing the nil case fixes that column
at the same time — previously a malicious sample was exported as
`label=0, severity_score=0`.

## `cmd/dataset/exporter/main.go`

Extracted `exportDirectory(dir, outPath string) (exportSummary, error)`, which
counts `rows` and `skipped`. A `ToCSVRow` error logs `EXCLUDED <file>` and skips
the row. `main` prints the row count and exits non-zero if anything was
excluded.

## Test files

- `internal/dataset/labels_test.go` (new)
- `cmd/dataset/labeler/main_test.go` (new)
- `cmd/dataset/validator/main_test.go` (new)
- `cmd/dataset/exporter/main_test.go` (new)
- `internal/output/json_writer_test.go` (2 tests added, 1 pre-existing test updated)

## Not changed

No BPF source, no regenerated object, no collector, no session schema, no
monitor. The session JSON format is unchanged — `label` was always a field, it
was simply never being set correctly.
