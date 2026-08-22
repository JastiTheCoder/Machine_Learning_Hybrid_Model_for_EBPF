package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
	"github.com/aniruddha/npm-ebpf-monitor/internal/session"
)

func TestJSONWriter_WriteSuccess(t *testing.T) {
	writer := NewJSONWriter(t.TempDir())

	record := SessionRecord{
		SessionID:   "test-123",
		PackageName: "lodash",
		Timestamp:   time.Date(2026, time.March, 18, 12, 0, 0, 0, time.UTC),
		Filetop: features.FiletopCounts{
			ReadProcesses:       5,
			WriteProcesses:      2,
			ReadDataTransferKB:  12,
			WriteDataTransferKB: 4,
			FileAccessProcesses: 6,
		},
		Install: features.InstallFeatures{
			TotalDependencies:    17,
			DirectDependencies:   4,
			IndirectDependencies: 13,
		},
		Opensnoop: map[string]int{
			"root_dir_access":       0,
			"temp_dir_access":       1,
			"home_dir_access":       2,
			"user_dir_access":       3,
			"sys_dir_access":        4,
			"etc_dir_access":        5,
			"other_dir_access":      6,
			"ssh_aws_wallet_access": 7,
		},
		TCP: features.TCPCounts{
			StateTransitions: 8,
			LocalIPs:         1,
			RemoteIPs:        2,
			LocalPorts:       3,
			RemotePorts:      4,
		},
		Syscalls: features.SyscallFeatures{
			IoOps:       9,
			FileOps:     8,
			NetworkOps:  7,
			TimeOps:     6,
			SecurityOps: 5,
			ProcessOps:  4,
			UnknownOps:  3,
		},
		Patterns: features.PatternCounts{
			P1:  1,
			P2:  2,
			P3:  3,
			P4:  4,
			P5:  5,
			P6:  6,
			P7:  7,
			P8:  8,
			P9:  9,
			P10: 10,
		},
		ProcessTree: "npm(123)->node(456)",
	}

	path, err := writer.Write(record)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("Write() path = %q, want absolute path", path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("json.Unmarshal(...) error = %v", err)
	}

	if got["session_id"] != "test-123" {
		t.Fatalf("session_id = %v, want %q", got["session_id"], "test-123")
	}
	if got["schema_version"] != CurrentSchemaVersion {
		t.Fatalf("schema_version = %v, want %q", got["schema_version"], CurrentSchemaVersion)
	}

	label, ok := got["label"]
	if !ok {
		t.Fatal("label key missing from marshaled JSON")
	}
	if label != nil {
		t.Fatalf("label = %v, want nil", label)
	}
}

func TestSessionRecord_ToCSVRow_LegacyUserlibAlias(t *testing.T) {
	// A label is required for export (see TestToCSVRowRefusesRecordWithNoLabel).
	// This test's subject is the opensnoop column alias, so any valid label
	// will do -- it just has to be present to reach the columns under test.
	label := 0
	record := SessionRecord{
		Label: &label,
		Opensnoop: map[string]int{
			"userlib_dir_access": 9,
		},
	}

	row, err := record.ToCSVRow()
	if err != nil {
		t.Fatalf("ToCSVRow() = %v, want nil error", err)
	}
	if len(row) != 39 {
		t.Fatalf("len(ToCSVRow()) = %d, want 39", len(row))
	}

	// Column index: 2 metadata + 5 filetop + 3 install +
	// opensnoop offsets (root=10, temp=11, home=12, user=13).
	if row[13] != "9" {
		t.Fatalf("user_dir_access column = %q, want %q", row[13], "9")
	}
}

func TestBuildRecord_NilSafety(t *testing.T) {
	sess := &session.Session{
		ID:            "nil-safe-session",
		PackageName:   "left-pad",
		StartTime:     time.Date(2026, time.March, 18, 10, 0, 0, 0, time.UTC),
		FiletopAgg:    nil,
		DirCounts:     nil,
		TCPAgg:        nil,
		NGramCtr:      nil,
		SyscallCounts: nil,
	}

	var (
		record   SessionRecord
		panicked any
	)

	func() {
		defer func() {
			panicked = recover()
		}()
		record = BuildRecord(sess, features.InstallFeatures{})
	}()

	if panicked != nil {
		t.Fatalf("BuildRecord(...) panicked: %v", panicked)
	}

	if record.Filetop != (features.FiletopCounts{}) {
		t.Fatalf("Filetop = %#v, want zero value", record.Filetop)
	}
	if record.TCP != (features.TCPCounts{}) {
		t.Fatalf("TCP = %#v, want zero value", record.TCP)
	}
	if record.Patterns != (features.PatternCounts{}) {
		t.Fatalf("Patterns = %#v, want zero value", record.Patterns)
	}
	if record.Syscalls != (features.SyscallFeatures{}) {
		t.Fatalf("Syscalls = %#v, want zero value", record.Syscalls)
	}

	wantOpensnoop := (&features.DirCounts{}).ToMap()
	if !reflect.DeepEqual(record.Opensnoop, wantOpensnoop) {
		t.Fatalf("Opensnoop = %#v, want %#v", record.Opensnoop, wantOpensnoop)
	}
}

func TestValidate(t *testing.T) {
	populated := SessionRecord{
		Filetop: features.FiletopCounts{
			FileAccessProcesses: 1,
		},
		Install: features.InstallFeatures{
			TotalDependencies: 1,
		},
		Syscalls: features.SyscallFeatures{
			IoOps: 1,
		},
		ProcessTree: "npm(123)",
	}

	if got := Validate(populated); len(got) != 0 {
		t.Fatalf("Validate(populated) returned %d warnings, want 0: %v", len(got), got)
	}

	empty := SessionRecord{}
	got := Validate(empty)

	wantWarnings := []string{
		"warning: syscalls.io_ops is 0 (missing syscall tracer data?)",
		"warning: filetop.file_access_processes is 0 (missing filetop tracer data?)",
		"warning: install.total_dependencies is 0 (missing package-lock/package.json data?)",
		"warning: process_tree is empty (missing process tracer data?)",
	}

	for _, want := range wantWarnings {
		if !slices.Contains(got, want) {
			t.Fatalf("Validate(empty) = %v, want warning %q", got, want)
		}
	}
}

// TestJSONWriterWritesInsideOutputDirForAwkwardPackageNames asserts that a
// package spec containing path separators still produces a readable session
// file inside the output directory.
//
// npm accepts specs like "./local-dep", "../pkg" and "@scope/pkg". Interpolating
// those straight into a filename either fails with ENOENT (the embedded "/" is
// read as a directory that does not exist) or, worse, escapes the output
// directory entirely. Either way the session's data is lost, and the monitor
// only logs it.
//
// The sanitisation applies to the *filename*; the record itself must still
// report the package name exactly as npm was invoked with it.
func TestJSONWriterWritesInsideOutputDirForAwkwardPackageNames(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
	}{
		{name: "relative path spec", packageName: "./localdep"},
		{name: "parent path spec", packageName: "../escapee"},
		{name: "nested path spec", packageName: "./a/b/c"},
		{name: "scoped package", packageName: "@scope/pkg"},
		{name: "file url spec", packageName: "file:../thing"},
		{name: "git url spec", packageName: "git+https://example.com/x.git"},
		{name: "bare parent", packageName: ".."},
		{name: "empty", packageName: ""},
		{name: "overlong", packageName: strings.Repeat("verylongname", 40)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputDir := t.TempDir()
			writer := NewJSONWriter(outputDir)

			record := SessionRecord{
				SessionID:   "npm-1787403056",
				PackageName: tt.packageName,
				Timestamp:   time.Date(2026, time.March, 18, 12, 0, 0, 0, time.UTC),
			}

			path, err := writer.Write(record)
			if err != nil {
				t.Fatalf("Write(package=%q) = %v, want nil", tt.packageName, err)
			}

			// The file must land in the output directory, not somewhere above it.
			if got := filepath.Dir(path); got != outputDir {
				t.Errorf("wrote to directory %q, want %q", got, outputDir)
			}

			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read back %s: %v", path, err)
			}

			var readBack SessionRecord
			if err := json.Unmarshal(payload, &readBack); err != nil {
				t.Fatalf("unmarshal %s: %v", path, err)
			}

			// Sanitising the filename must not alter the recorded data.
			if readBack.PackageName != tt.packageName {
				t.Errorf("record package_name = %q, want %q", readBack.PackageName, tt.packageName)
			}
			if readBack.SessionID != record.SessionID {
				t.Errorf("record session_id = %q, want %q", readBack.SessionID, record.SessionID)
			}
		})
	}
}

// TestJSONWriterKeepsOrdinaryPackageNamesInFilename pins the filenames produced
// for the package names the project actually captures, so that sanitisation
// cannot quietly rename them.
//
// This matters beyond cosmetics: the dataset labeller keys off substrings of the
// filename, so a scheme that rewrote "suspicious-test-1.0.0.tgz" would silently
// change ground-truth labels.
//
// This test passes both before and after the sanitisation change. It is a
// regression guard, not a TDD slice.
func TestJSONWriterKeepsOrdinaryPackageNamesInFilename(t *testing.T) {
	names := []string{
		"lodash",
		"benign-test-1.0.0.tgz",
		"suspicious-test-1.0.0.tgz",
		"ci-secret-grabber-test-1.0.0.tgz",
		"crypto-miner-test-1.0.0.tgz",
		"env-stealer-test-1.0.0.tgz",
		"reverse-shell-test-1.0.0.tgz",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			outputDir := t.TempDir()
			writer := NewJSONWriter(outputDir)

			path, err := writer.Write(SessionRecord{
				SessionID:   "npm-1787403056",
				PackageName: name,
				Timestamp:   time.Date(2026, time.March, 18, 12, 0, 0, 0, time.UTC),
			})
			if err != nil {
				t.Fatalf("Write(package=%q) = %v, want nil", name, err)
			}

			want := "npm-1787403056_" + name + ".json"
			if got := filepath.Base(path); got != want {
				t.Errorf("filename = %q, want %q", got, want)
			}
		})
	}
}

// TestToCSVRowRefusesRecordWithNoLabel asserts that a record whose label was
// never assigned cannot be turned into a training row.
//
// This is the last line of defense for C4. Even with the labeler fixed, a
// session can reach the exporter unlabelled -- the labeler was skipped, it
// failed on that file, or the file was captured after the last labelling run.
// The previous behaviour turned that missing label into a confident "0" and
// wrote it straight into the training CSV, indistinguishable from a genuinely
// benign sample.
func TestToCSVRowRefusesRecordWithNoLabel(t *testing.T) {
	record := SessionRecord{
		SessionID:   "npm-1787403056",
		PackageName: "crypto-miner-test-1.0.0.tgz",
		Label:       nil,
	}

	row, err := record.ToCSVRow()
	if err == nil {
		t.Fatalf("ToCSVRow() with nil label = %v, nil; want an error", row)
	}
	if row != nil {
		t.Errorf("ToCSVRow() returned a row alongside its error: %v; want no row", row)
	}
}

// TestToCSVRowUsesTheAssignedLabel asserts a labelled record still exports, and
// that the label and severity columns carry the assigned value.
//
// Expected column indices come from the documented column order on ToCSVRow
// (package_name, label, ... severity_score last), not from the implementation.
func TestToCSVRowUsesTheAssignedLabel(t *testing.T) {
	tests := []struct {
		name  string
		label int
	}{
		{name: "benign", label: 0},
		{name: "malicious", label: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			label := tt.label
			record := SessionRecord{
				SessionID:   "npm-1787403056",
				PackageName: "crypto-miner-test-1.0.0.tgz",
				Label:       &label,
			}

			row, err := record.ToCSVRow()
			if err != nil {
				t.Fatalf("ToCSVRow() = %v, want nil error", err)
			}

			want := strconv.Itoa(tt.label)
			if got := row[1]; got != want {
				t.Errorf("label column = %q, want %q", got, want)
			}
			if got := row[len(row)-1]; got != want {
				t.Errorf("severity_score column = %q, want %q", got, want)
			}
		})
	}
}
