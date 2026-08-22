package main

import (
	"errors"
	"testing"

	"github.com/aniruddha/npm-ebpf-monitor/internal/dataset"
	"github.com/aniruddha/npm-ebpf-monitor/internal/output"
)

// TestDerivedLabelPrefersTheStoredLabel asserts that a label already written
// into the record wins over any inference.
//
// The labeler is the authority. If it has run, the validator must validate what
// is actually in the dataset, not re-derive its own opinion of it.
func TestDerivedLabelPrefersTheStoredLabel(t *testing.T) {
	stored := 1
	rec := output.SessionRecord{
		PackageName: "benign-test-1.0.0.tgz", // table says 0; stored says 1
		Label:       &stored,
	}

	got, err := derivedLabel("npm-1_benign-test-1.0.0.tgz.json", rec)
	if err != nil {
		t.Fatalf("derivedLabel = %v, want nil error", err)
	}
	if got != 1 {
		t.Errorf("derivedLabel = %d, want 1 (the stored label, not the table's)", got)
	}
}

// TestDerivedLabelFallsBackToDeclaredGroundTruth asserts that an unlabelled
// record resolves through the shared ground-truth table.
//
// Before the fix this fell back to a "suspicious" substring match duplicated
// from the labeler -- so an unlabelled crypto-miner-test session validated as
// benign, exactly as it did in the labeler. Routing both through one table is
// what stops the two tools from disagreeing.
func TestDerivedLabelFallsBackToDeclaredGroundTruth(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
		want        int
	}{
		{name: "benign fixture", packageName: "benign-test-1.0.0.tgz", want: 0},
		{name: "cryptominer fixture", packageName: "crypto-miner-test-1.0.0.tgz", want: 1},
		{name: "env stealer fixture", packageName: "env-stealer-test-1.0.0.tgz", want: 1},
		{name: "CI secret grabber fixture", packageName: "ci-secret-grabber-test-1.0.0.tgz", want: 1},
		{name: "reverse shell fixture", packageName: "reverse-shell-test-1.0.0.tgz", want: 1},
		{name: "generic suspicious fixture", packageName: "suspicious-test-1.0.0.tgz", want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := output.SessionRecord{PackageName: tt.packageName, Label: nil}

			got, err := derivedLabel("npm-1_"+tt.packageName+".json", rec)
			if err != nil {
				t.Fatalf("derivedLabel(%q) = %v, want nil error", tt.packageName, err)
			}
			if got != tt.want {
				t.Errorf("derivedLabel(%q) = %d, want %d", tt.packageName, got, tt.want)
			}
		})
	}
}

// TestDerivedLabelRejectsUndeclaredPackage asserts that an unlabelled record for
// a package with no declared ground truth is an error, not a benign default.
func TestDerivedLabelRejectsUndeclaredPackage(t *testing.T) {
	rec := output.SessionRecord{PackageName: "keylogger-test-1.0.0.tgz", Label: nil}

	got, err := derivedLabel("npm-1_keylogger-test-1.0.0.tgz.json", rec)
	if err == nil {
		t.Fatalf("derivedLabel = %d, nil; want an error for an undeclared package", got)
	}
	if !errors.Is(err, dataset.ErrUnknownPackage) {
		t.Errorf("error = %v, want it to wrap dataset.ErrUnknownPackage", err)
	}
}
