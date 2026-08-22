// Package dataset holds the ground truth for the packages this project
// captures: which fixture is malicious, which is benign, and what kind of
// behaviour each one simulates.
//
// It exists because that ground truth is the single most load-bearing signal in
// the project -- it is the training label for the Random Forest classifier the
// whole pipeline feeds. Deriving it from a substring match on a filename, as
// the labeler and validator each previously did independently, meant a fixture
// whose name did not happen to contain "suspicious" was silently labelled
// benign. See docs/fix-c4-ground-truth-labels/.
package dataset

import (
	"errors"
	"fmt"
	"strings"
)

// FixtureLabel is the declared ground truth for one fixture package.
type FixtureLabel struct {
	// Label is the binary training label: 0 = benign, 1 = malicious.
	Label int
	// Category names the behaviour the fixture simulates. It is descriptive
	// only -- the classifier trains on Label -- but it makes the table
	// self-documenting and gives the dataset a finer-grained grouping if one
	// is ever needed.
	Category string
}

// fixtureLabels is the authoritative fixture -> ground truth mapping.
//
// Keys are the fixture's base name, without the version-and-extension suffix
// that npm appends when the package is installed from a tarball (so
// "crypto-miner-test" covers "crypto-miner-test-1.0.0.tgz" and any other
// version of it).
//
// Adding a new fixture to the corpus REQUIRES adding it here. That is
// deliberate: Lookup rejects anything absent from this table rather than
// guessing, so a new package cannot reach the training set with an unexamined
// label.
var fixtureLabels = map[string]FixtureLabel{
	"benign-test":            {Label: 0, Category: "benign"},
	"suspicious-test":        {Label: 1, Category: "generic-suspicious"},
	"crypto-miner-test":      {Label: 1, Category: "cryptomining"},
	"env-stealer-test":       {Label: 1, Category: "credential-theft"},
	"ci-secret-grabber-test": {Label: 1, Category: "credential-theft"},
	"reverse-shell-test":     {Label: 1, Category: "remote-access"},
}

// ErrUnknownPackage is returned by Lookup for a package absent from the
// ground-truth table. Callers can test for it with errors.Is.
var ErrUnknownPackage = errors.New("package has no declared ground-truth label")

// Lookup returns the declared ground truth for a package spec.
//
// An undeclared package is an error, never a default. The bug this replaces
// (AUDIT.md C4) defaulted to benign, which silently mislabelled 8 of the 10
// malicious samples in the captured corpus. Refusing to guess means a new
// package stops the pipeline until somebody declares what it actually is --
// loud and fixable, rather than quiet and wrong.
func Lookup(packageSpec string) (FixtureLabel, error) {
	key := fixtureKey(packageSpec)

	label, ok := fixtureLabels[key]
	if !ok {
		return FixtureLabel{}, fmt.Errorf("%w: %q (resolved to key %q); add it to "+
			"fixtureLabels in internal/dataset/labels.go", ErrUnknownPackage, packageSpec, key)
	}
	return label, nil
}

// fixtureKey reduces a package spec as it appears in a session record
// ("crypto-miner-test-1.0.0.tgz") to its table key ("crypto-miner-test").
func fixtureKey(packageSpec string) string {
	key := strings.TrimSpace(packageSpec)
	key = strings.TrimSuffix(key, ".tgz")

	// Strip a trailing "-<version>" segment, e.g. "-1.0.0".
	if i := strings.LastIndex(key, "-"); i > 0 {
		if isVersion(key[i+1:]) {
			key = key[:i]
		}
	}
	return key
}

// isVersion reports whether s looks like a dotted numeric version ("1.0.0").
func isVersion(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return strings.ContainsRune(s, '.')
}
