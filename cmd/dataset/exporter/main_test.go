package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aniruddha/npm-ebpf-monitor/internal/output"
)

// writeSession writes one session JSON into dir. A nil label is written as
// "label": null, which is exactly what an unlabelled capture looks like on disk.
func writeSession(t *testing.T, dir, sessionID, packageName string, label *int) {
	t.Helper()

	rec := output.SessionRecord{
		SchemaVersion: output.CurrentSchemaVersion,
		SessionID:     sessionID,
		PackageName:   packageName,
		Label:         label,
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("marshal session %s: %v", sessionID, err)
	}

	path := filepath.Join(dir, sessionID+"_"+packageName+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write session %s: %v", sessionID, err)
	}
}

// readCSV returns the rows of a CSV file, excluding the header.
func readCSV(t *testing.T, path string) [][]string {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open csv %s: %v", path, err)
	}
	t.Cleanup(func() { f.Close() })

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read csv %s: %v", path, err)
	}
	if len(rows) == 0 {
		t.Fatalf("csv %s has no header row", path)
	}
	return rows[1:]
}

func intPtr(v int) *int { return &v }

// TestExportDirectoryWritesTheAssignedLabel asserts labelled sessions reach the
// CSV with the label they were assigned.
//
// Column index 1 is `label`, per the documented column order on ToCSVRow
// (package_name, label, ...).
func TestExportDirectoryWritesTheAssignedLabel(t *testing.T) {
	dir := t.TempDir()
	writeSession(t, dir, "npm-1", "benign-test-1.0.0.tgz", intPtr(0))
	writeSession(t, dir, "npm-2", "crypto-miner-test-1.0.0.tgz", intPtr(1))
	writeSession(t, dir, "npm-3", "reverse-shell-test-1.0.0.tgz", intPtr(1))

	out := filepath.Join(t.TempDir(), "dataset.csv")

	sum, err := exportDirectory(dir, out)
	if err != nil {
		t.Fatalf("exportDirectory = %v, want nil", err)
	}
	if sum.rows != 3 {
		t.Errorf("exported rows = %d, want 3", sum.rows)
	}
	if sum.skipped != 0 {
		t.Errorf("skipped = %d, want 0", sum.skipped)
	}

	wantLabels := map[string]string{
		"benign-test-1.0.0.tgz":        "0",
		"crypto-miner-test-1.0.0.tgz":  "1",
		"reverse-shell-test-1.0.0.tgz": "1",
	}

	rows := readCSV(t, out)
	if len(rows) != 3 {
		t.Fatalf("csv has %d data rows, want 3", len(rows))
	}

	for _, row := range rows {
		pkg, label := row[0], row[1]
		want, ok := wantLabels[pkg]
		if !ok {
			t.Errorf("unexpected package %q in csv", pkg)
			continue
		}
		if label != want {
			t.Errorf("package %q: label column = %q, want %q", pkg, label, want)
		}
	}
}

// TestExportDirectoryRefusesUnlabelledSessions is the end-to-end statement of
// the C4 fix: an unlabelled malicious session must never reach the training CSV
// wearing a benign label.
//
// Before the fix, a record with "label": null was exported as label=0,
// severity_score=0 -- a crypto miner presented to the classifier as a benign
// example, with no warning and no diagnostic trail.
func TestExportDirectoryRefusesUnlabelledSessions(t *testing.T) {
	dir := t.TempDir()
	writeSession(t, dir, "npm-1", "crypto-miner-test-1.0.0.tgz", nil)
	writeSession(t, dir, "npm-2", "reverse-shell-test-1.0.0.tgz", nil)
	writeSession(t, dir, "npm-3", "benign-test-1.0.0.tgz", intPtr(0))

	out := filepath.Join(t.TempDir(), "dataset.csv")

	sum, err := exportDirectory(dir, out)
	if err != nil {
		t.Fatalf("exportDirectory = %v, want nil", err)
	}

	if sum.skipped != 2 {
		t.Errorf("skipped = %d, want 2 (the two unlabelled sessions)", sum.skipped)
	}
	if sum.rows != 1 {
		t.Errorf("exported rows = %d, want 1 (only the labelled session)", sum.rows)
	}

	rows := readCSV(t, out)
	for _, row := range rows {
		pkg, label := row[0], row[1]
		if pkg != "benign-test-1.0.0.tgz" {
			t.Errorf("unlabelled session %q reached the CSV with label %q; it must be "+
				"refused, not defaulted", pkg, label)
		}
	}

	// The severity column must not have been invented either.
	for _, row := range rows {
		if got := row[len(row)-1]; got != "0" {
			t.Errorf("severity_score = %q for the one benign row, want %q", got, "0")
		}
	}

}
