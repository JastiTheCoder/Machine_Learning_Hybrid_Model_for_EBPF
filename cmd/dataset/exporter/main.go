// Package main implements a CSV exporter for npm-ebpf-monitor session records.
//
// Usage:
//
//	go run ./cmd/dataset/exporter --dir ./sessions/dataset/ --out ./sessions/sessions.csv
//
// It reads every JSON file in --dir, unmarshals each into a SessionRecord,
// calls ToCSVRow() for the 39-column feature vector, and writes the result to
// the CSV file specified by --out.  A header row is written first.
//
// Exit codes:
//
//	0  success
//	1  flag / I-O error
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aniruddha/npm-ebpf-monitor/internal/output"
)

// csvHeader lists the 39 column names in the same order as ToCSVRow().
// Layout: 2 metadata + 36 QUT-DV25 features + 1 trailing metadata.
var csvHeader = []string{
	// metadata
	"package_name",
	"label",
	// filetop (5)
	"read_processes",
	"write_processes",
	"read_data_transfer_kb",
	"write_data_transfer_kb",
	"file_access_processes",
	// install (3)
	"total_dependencies",
	"direct_dependencies",
	"indirect_dependencies",
	// opensnoop / dir counts (7)
	"root_dir_access",
	"temp_dir_access",
	"home_dir_access",
	"user_dir_access",
	"sys_dir_access",
	"etc_dir_access",
	"other_dir_access",
	// tcp (5)
	"state_transitions",
	"local_ips",
	"remote_ips",
	"local_ports",
	"remote_ports",
	// syscalls (6)
	"io_ops",
	"file_ops",
	"network_ops",
	"time_ops",
	"security_ops",
	"process_ops",
	// patterns (10)
	"p1_file_metadata",
	"p2_read_data",
	"p3_write_data",
	"p4_socket_create",
	"p5_process_create",
	"p6_memory_map",
	"p7_fd_manage",
	"p8_ipc",
	"p9_file_lock",
	"p10_error_handle",
	// severity metadata
	"severity_score",
}

// exportSummary counts the outcome of an export run.
type exportSummary struct {
	rows    int
	skipped int
}

func main() {
	dir := flag.String("dir", "", "Path to the sessions directory containing JSON files (required)")
	out := flag.String("out", "sessions.csv", "Output CSV file path")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "error: --dir is required")
		flag.Usage()
		os.Exit(1)
	}

	sum, err := exportDirectory(*dir, *out)
	if err != nil {
		log.Fatalf("export failed: %v", err)
	}

	fmt.Printf("Wrote %d rows to %s.\n", sum.rows, *out)

	if sum.skipped > 0 {
		fmt.Fprintf(os.Stderr,
			"\nEXCLUDED: %d session(s) were not exported because they have no label. "+
				"Run the labeler over the sessions directory, then export again.\n", sum.skipped)
		os.Exit(1)
	}
}

// exportDirectory writes every labelled session JSON in dir to a CSV at
// outPath, returning how many rows it wrote and how many sessions it refused.
//
// A session with no label is skipped, never defaulted. Defaulting it -- which
// is what this tool used to do -- put genuinely malicious samples into the
// training set labelled benign, with no warning (AUDIT.md C4).
func exportDirectory(dir, outPath string) (exportSummary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return exportSummary{}, fmt.Errorf("cannot read directory %q: %w", dir, err)
	}

	outFile, err := os.Create(outPath)
	if err != nil {
		return exportSummary{}, fmt.Errorf("cannot create output file %q: %w", outPath, err)
	}
	defer outFile.Close()

	w := csv.NewWriter(outFile)

	if err := w.Write(csvHeader); err != nil {
		return exportSummary{}, fmt.Errorf("cannot write CSV header: %w", err)
	}

	var sum exportSummary

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(dir, entry.Name())

		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("SKIP %s: read error: %v", entry.Name(), err)
			sum.skipped++
			continue
		}

		var record output.SessionRecord
		if err := json.Unmarshal(data, &record); err != nil {
			log.Printf("SKIP %s: unmarshal error: %v", entry.Name(), err)
			sum.skipped++
			continue
		}

		row, err := record.ToCSVRow()
		if err != nil {
			log.Printf("EXCLUDED %s: %v", entry.Name(), err)
			sum.skipped++
			continue
		}

		if err := w.Write(row); err != nil {
			log.Printf("SKIP %s: csv write error: %v", entry.Name(), err)
			sum.skipped++
			continue
		}

		sum.rows++
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return sum, fmt.Errorf("csv flush error: %w", err)
	}

	return sum, nil
}
