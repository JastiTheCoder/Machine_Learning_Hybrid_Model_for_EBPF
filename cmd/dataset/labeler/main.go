// Package main implements a dataset labeler for npm-ebpf-monitor session records.
//
// It reads every JSON file in the --dir directory, resolves the session's
// ground-truth label from the declared fixture table in internal/dataset,
// writes back label=1 (malicious) or label=0 (benign), and prints a summary.
//
// A package with no declared ground truth is reported as a failure and left
// unlabelled -- it is never guessed at. See docs/fix-c4-ground-truth-labels/.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aniruddha/npm-ebpf-monitor/internal/dataset"
)

// summary counts the outcome of a labelling run.
type summary struct {
	benign    int
	malicious int
	failed    int
}

func main() {
	dir := flag.String("dir", "", "Path to the sessions directory (required)")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "error: --dir is required")
		flag.Usage()
		os.Exit(1)
	}

	sum, err := labelDirectory(*dir)
	if err != nil {
		log.Fatalf("cannot label directory %q: %v", *dir, err)
	}

	total := sum.benign + sum.malicious
	fmt.Printf("\nDataset: %d benign, %d malicious (%d total)\n", sum.benign, sum.malicious, total)

	if sum.failed > 0 {
		fmt.Fprintf(os.Stderr,
			"\nUNLABELLED: %d session(s) have no declared ground truth and were left "+
				"unlabelled. They must not be exported for training until declared in "+
				"internal/dataset/labels.go.\n", sum.failed)
		os.Exit(1)
	}
}

// labelDirectory labels every session JSON in dir, rewriting each file in place.
//
// It returns an error only when the directory itself cannot be processed;
// per-file problems are counted in the returned summary so that one bad file
// does not abandon the rest of the run.
func labelDirectory(dir string) (summary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return summary{}, err
	}

	var sum summary

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(dir, entry.Name())

		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("SKIP %s: read error: %v", entry.Name(), err)
			sum.failed++
			continue
		}

		// Unmarshal into a generic map to preserve all existing keys exactly.
		var record map[string]interface{}
		if err := json.Unmarshal(data, &record); err != nil {
			log.Printf("SKIP %s: unmarshal error: %v", entry.Name(), err)
			sum.failed++
			continue
		}

		spec := packageSpecOf(entry.Name(), record)

		truth, err := dataset.Lookup(spec)
		if err != nil {
			// Deliberately leave the file unlabelled rather than guessing. A
			// wrong label is worse than a missing one: it reaches the training
			// set looking like ground truth.
			log.Printf("UNLABELLED %s: %v", entry.Name(), err)
			sum.failed++
			continue
		}

		record["label"] = truth.Label

		out, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			log.Printf("SKIP %s: marshal error: %v", entry.Name(), err)
			sum.failed++
			continue
		}

		if err := os.WriteFile(path, out, 0o644); err != nil {
			log.Printf("SKIP %s: write error: %v", entry.Name(), err)
			sum.failed++
			continue
		}

		if truth.Label == 1 {
			sum.malicious++
			fmt.Printf("  [malicious] %-52s %s\n", entry.Name(), truth.Category)
		} else {
			sum.benign++
			fmt.Printf("  [benign]    %-52s %s\n", entry.Name(), truth.Category)
		}
	}

	return sum, nil
}

// packageSpecOf returns the package spec to resolve ground truth from,
// preferring the record's own package_name and falling back to the filename.
func packageSpecOf(filename string, record map[string]interface{}) string {
	if pkg, ok := record["package_name"].(string); ok && strings.TrimSpace(pkg) != "" {
		return pkg
	}

	// Filenames are "<session-id>_<package spec>.json".
	name := strings.TrimSuffix(filename, ".json")
	if i := strings.Index(name, "_"); i >= 0 {
		return name[i+1:]
	}
	return name
}
