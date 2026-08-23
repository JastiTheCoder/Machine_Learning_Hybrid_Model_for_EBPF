package dataset

import (
	"strings"
	"testing"
)

// TestLookupResolvesGroundTruthForEachCorpusFixture pins the ground-truth label
// and category for every fixture package the project captures.
//
// These expected values are NOT derived from the lookup table -- they are
// written out independently from what each fixture is documented to do:
// AUDIT.md's C4 finding names crypto-miner-test, env-stealer-test,
// ci-secret-grabber-test and reverse-shell-test as "genuinely malicious test
// fixtures" and "attack-simulation fixtures", alongside suspicious-test. Only
// benign-test is benign. A test that recomputed these from the table it is
// checking would pass by construction and could never disagree with it.
func TestLookupResolvesGroundTruthForEachCorpusFixture(t *testing.T) {
	tests := []struct {
		name         string
		packageSpec  string
		wantLabel    int
		wantCategory string
	}{
		{
			name:         "benign fixture",
			packageSpec:  "benign-test-1.0.0.tgz",
			wantLabel:    0,
			wantCategory: "benign",
		},
		{
			name:         "generic suspicious fixture",
			packageSpec:  "suspicious-test-1.0.0.tgz",
			wantLabel:    1,
			wantCategory: "generic-suspicious",
		},
		{
			name:         "cryptominer fixture",
			packageSpec:  "crypto-miner-test-1.0.0.tgz",
			wantLabel:    1,
			wantCategory: "cryptomining",
		},
		{
			name:         "environment stealer fixture",
			packageSpec:  "env-stealer-test-1.0.0.tgz",
			wantLabel:    1,
			wantCategory: "credential-theft",
		},
		{
			name:         "CI secret grabber fixture",
			packageSpec:  "ci-secret-grabber-test-1.0.0.tgz",
			wantLabel:    1,
			wantCategory: "credential-theft",
		},
		{
			name:         "reverse shell fixture",
			packageSpec:  "reverse-shell-test-1.0.0.tgz",
			wantLabel:    1,
			wantCategory: "remote-access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Lookup(tt.packageSpec)
			if err != nil {
				t.Fatalf("Lookup(%q) returned error %v, want a label", tt.packageSpec, err)
			}
			if got.Label != tt.wantLabel {
				t.Errorf("Lookup(%q).Label = %d, want %d", tt.packageSpec, got.Label, tt.wantLabel)
			}
			if got.Category != tt.wantCategory {
				t.Errorf("Lookup(%q).Category = %q, want %q", tt.packageSpec, got.Category, tt.wantCategory)
			}
		})
	}
}

// TestLookupRejectsUndeclaredPackages asserts that a package absent from the
// ground-truth table produces an error rather than a label.
//
// This is the heart of the C4 fix. The defect was not that the old heuristic
// computed a wrong answer -- it was that it always computed *an* answer, and
// its fallback answer was "benign". Any package whose name did not contain
// "suspicious" was confidently labelled 0 and exported into the training set.
//
// So the property under test is not "unknown names return an error code"; it is
// "an undeclared package can never be mistaken for a benign sample". The
// assertion below therefore checks both that an error is returned AND that no
// usable benign label comes back alongside it.
func TestLookupRejectsUndeclaredPackages(t *testing.T) {
	tests := []struct {
		name        string
		packageSpec string
	}{
		{name: "real registry package", packageSpec: "react"},
		{name: "versioned registry package", packageSpec: "axios-1.6.0.tgz"},
		{name: "undeclared fixture", packageSpec: "keylogger-test-1.0.0.tgz"},
		{name: "empty spec", packageSpec: ""},
		{name: "near miss on a declared name", packageSpec: "crypto-miner-tes-1.0.0.tgz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Lookup(tt.packageSpec)
			if err == nil {
				t.Fatalf("Lookup(%q) = %+v, nil; want an error for an undeclared package",
					tt.packageSpec, got)
			}
			if got.Label == 0 && got.Category == "benign" {
				t.Errorf("Lookup(%q) returned a benign label alongside its error; an "+
					"undeclared package must never look benign", tt.packageSpec)
			}
		})
	}
}

// TestLookupErrorNamesTheOffendingPackage asserts the error is diagnosable.
//
// When a capture run fails because a package is undeclared, the operator needs
// to know which one without re-running anything.
func TestLookupErrorNamesTheOffendingPackage(t *testing.T) {
	_, err := Lookup("keylogger-test-1.0.0.tgz")
	if err == nil {
		t.Fatal("Lookup returned nil error for an undeclared package")
	}
	if !strings.Contains(err.Error(), "keylogger-test") {
		t.Errorf("error %q does not name the offending package", err.Error())
	}
}
