package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusDir is the project's captured session corpus, relative to this package.
const corpusDir = "../../../sessions"

// expectedLabels is the ground truth for the corpus fixtures, written out here
// independently of internal/dataset's table.
//
// If this duplicated the production table -- or called dataset.Lookup to
// compute what it expects -- it would pass by construction and could never
// disagree with the code it is checking. These values come from AUDIT.md's C4
// finding, which names crypto-miner-test, env-stealer-test,
// ci-secret-grabber-test and reverse-shell-test as genuinely malicious
// attack-simulation fixtures, alongside suspicious-test.
var expectedLabels = map[string]int{
	"benign-test":            0,
	"suspicious-test":        1,
	"crypto-miner-test":      1,
	"env-stealer-test":       1,
	"ci-secret-grabber-test": 1,
	"reverse-shell-test":     1,
	// lodash: a real, unmodified npm-registry package, captured pre-verdict-
	// engine to seed the corpus with a genuine benign-real-world sample. See
	// internal/dataset/labels.go and docs/new-features/001-verdict-scoring-engine/.
	"lodash": 0,
}

// copyCorpusToTemp copies the real session corpus into a temp directory, so the
// labeler (which rewrites files in place) never touches the tracked originals.
func copyCorpusToTemp(t *testing.T) string {
	t.Helper()

	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Skipf("session corpus not available at %s: %v", corpusDir, err)
	}

	dir := t.TempDir()
	copied := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(corpusDir, e.Name()))
		if err != nil {
			t.Fatalf("read corpus file %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			t.Fatalf("write temp copy of %s: %v", e.Name(), err)
		}
		copied++
	}

	if copied == 0 {
		t.Skip("session corpus contains no JSON files")
	}
	return dir
}

// fixtureBaseName reduces a corpus filename to the fixture it captured, e.g.
// "npm-1776924424_crypto-miner-test-1.0.0.tgz.json" -> "crypto-miner-test".
func fixtureBaseName(t *testing.T, filename string) string {
	t.Helper()

	name := strings.TrimSuffix(filename, ".json")
	if i := strings.Index(name, "_"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(name, ".tgz")
	if i := strings.LastIndex(name, "-"); i > 0 {
		name = name[:i] // drop the version segment
	}
	return name
}

// TestLabelDirectoryLabelsEveryCorpusFixtureCorrectly is the direct regression
// of the observed C4 failure.
//
// Before the fix, running the labeler over this exact corpus reported
// "Dataset: 11 benign, 2 malicious (13 total)" -- 8 of the 10 malicious samples
// were written back with label=0, because only "suspicious-test" contains the
// substring the old heuristic matched on. Those 8 rows would then have been
// exported into the Random Forest training set as benign examples of a
// reverse shell, a crypto miner, a credential stealer and a CI secret grabber.
func TestLabelDirectoryLabelsEveryCorpusFixtureCorrectly(t *testing.T) {
	dir := copyCorpusToTemp(t)

	sum, err := labelDirectory(dir)
	if err != nil {
		t.Fatalf("labelDirectory(%s) = %v, want nil", dir, err)
	}

	// Every file must carry the label its fixture actually warrants.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}

	var wantBenign, wantMalicious int
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}

		base := fixtureBaseName(t, e.Name())
		want, known := expectedLabels[base]
		if !known {
			t.Fatalf("corpus file %s has fixture %q with no expected label in this test; "+
				"update expectedLabels", e.Name(), base)
		}
		if want == 1 {
			wantMalicious++
		} else {
			wantBenign++
		}

		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}

		var record struct {
			Label *int `json:"label"`
		}
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatalf("unmarshal %s: %v", e.Name(), err)
		}

		if record.Label == nil {
			t.Errorf("%s: label is null after labelling, want %d", e.Name(), want)
			continue
		}
		if *record.Label != want {
			t.Errorf("%s (fixture %q): label = %d, want %d", e.Name(), base, *record.Label, want)
		}
	}

	if sum.malicious != wantMalicious {
		t.Errorf("summary malicious = %d, want %d", sum.malicious, wantMalicious)
	}
	if sum.benign != wantBenign {
		t.Errorf("summary benign = %d, want %d", sum.benign, wantBenign)
	}
	if sum.failed != 0 {
		t.Errorf("summary failed = %d, want 0", sum.failed)
	}
}
