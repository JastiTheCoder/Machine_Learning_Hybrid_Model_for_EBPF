package output

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
	"github.com/aniruddha/npm-ebpf-monitor/internal/session"
	"github.com/aniruddha/npm-ebpf-monitor/internal/verdict"
)

// CurrentSchemaVersion history:
//
//	1.0.0 -> 1.1.0  added the "verdict" block
//	1.1.0 -> 1.2.0  added the "sensitive" block
//
// Both additions are new top-level keys, so a reader of an older version that
// ignores unknown keys still works, and an older file missing the key still
// unmarshals (the field stays zero-valued).
//
// 1.2.0 is the first version whose feature set is not constrained to
// QUT-DV25's 36 columns. That dataset was retired as a training source after
// it was shown to transfer with the wrong sign -- see
// ml_analysis/QUT_RETIREMENT.md -- so matching its schema no longer buys
// anything, and the credential evidence the monitor already gathers can
// finally reach the model.
const CurrentSchemaVersion = "1.2.0"

// SessionRecord is the persisted JSON representation of one monitored session.
type SessionRecord struct {
	SchemaVersion string                   `json:"schema_version"`
	SessionID     string                   `json:"session_id"`
	PackageName   string                   `json:"package_name"`
	Timestamp     time.Time                `json:"timestamp"`
	Label         *int                     `json:"label"`
	Filetop       features.FiletopCounts   `json:"filetop"`
	Install       features.InstallFeatures `json:"install"`
	Opensnoop     map[string]int           `json:"opensnoop"`
	TCP           features.TCPCounts       `json:"tcp"`
	Syscalls      features.SyscallFeatures `json:"syscalls"`
	Patterns      features.PatternCounts   `json:"patterns"`
	Sensitive     features.SensitiveAccess `json:"sensitive"`
	ProcessTree   string                   `json:"process_tree"`
	TimedOut      bool                     `json:"timed_out"`
	Verdict       *verdict.Verdict         `json:"verdict"`
}

// ToCSVRow returns a slice of strings representing this record as a CSV row.
//
// Column order (59 total = 2 metadata + 36 legacy features + 20 sensitive +
// 1 trailing metadata):
//
//	package_name, label,
//	read_processes, write_processes, read_data_transfer_kb, write_data_transfer_kb, file_access_processes,
//	total_dependencies, direct_dependencies, indirect_dependencies,
//	root_dir_access, temp_dir_access, home_dir_access, user_dir_access, sys_dir_access, etc_dir_access, other_dir_access,
//	state_transitions, local_ips, remote_ips, local_ports, remote_ports,
//	io_ops, file_ops, network_ops, time_ops, security_ops, process_ops,
//	p1_file_metadata, p2_read_data, p3_write_data, p4_socket_create, p5_process_create,
//	p6_memory_map, p7_fd_manage, p8_ipc, p9_file_lock, p10_error_handle,
//	<20 columns from features.SensitiveAccessColumns()>,
//	severity_score
//
// The first 36 feature columns are retained unchanged so previously exported
// datasets stay comparable, not because QUT-DV25 still requires them.
func (s *SessionRecord) ToCSVRow() ([]string, error) {
	// An unassigned label is refused rather than defaulted. Defaulting it to
	// "0" is what let genuinely malicious sessions reach the training set
	// labelled benign (AUDIT.md C4): once written, a missing label and a
	// benign label are indistinguishable, so the mistake leaves no diagnostic
	// trail. Refusing keeps the dataset honest at the cost of a loud failure.
	if s.Label == nil {
		return nil, fmt.Errorf("session %q (package %q) has no label; run the labeler "+
			"before exporting", s.SessionID, s.PackageName)
	}
	labelStr := strconv.Itoa(*s.Label)

	opensnoop := normalizeOpensnoop(s.Opensnoop)
	osGet := func(key string) string {
		return strconv.Itoa(opensnoop[key])
	}

	// severity_score: mirrors label for ML team baseline (0 = benign, 1 = malicious)
	severityScore := labelStr

	row := []string{
		// metadata
		s.PackageName,
		labelStr,
		// filetop (5)
		strconv.Itoa(s.Filetop.ReadProcesses),
		strconv.Itoa(s.Filetop.WriteProcesses),
		strconv.Itoa(s.Filetop.ReadDataTransferKB),
		strconv.Itoa(s.Filetop.WriteDataTransferKB),
		strconv.Itoa(s.Filetop.FileAccessProcesses),
		// install (3)
		strconv.Itoa(s.Install.TotalDependencies),
		strconv.Itoa(s.Install.DirectDependencies),
		strconv.Itoa(s.Install.IndirectDependencies),
		// opensnoop / dir counts (7)
		osGet("root_dir_access"),
		osGet("temp_dir_access"),
		osGet("home_dir_access"),
		osGet("user_dir_access"),
		osGet("sys_dir_access"),
		osGet("etc_dir_access"),
		osGet("other_dir_access"),
		// tcp (5)
		strconv.Itoa(s.TCP.StateTransitions),
		strconv.Itoa(s.TCP.LocalIPs),
		strconv.Itoa(s.TCP.RemoteIPs),
		strconv.Itoa(s.TCP.LocalPorts),
		strconv.Itoa(s.TCP.RemotePorts),
		// syscalls (6)
		strconv.Itoa(s.Syscalls.IoOps),
		strconv.Itoa(s.Syscalls.FileOps),
		strconv.Itoa(s.Syscalls.NetworkOps),
		strconv.Itoa(s.Syscalls.TimeOps),
		strconv.Itoa(s.Syscalls.SecurityOps),
		strconv.Itoa(s.Syscalls.ProcessOps),
		// patterns (10)
		strconv.Itoa(s.Patterns.P1),
		strconv.Itoa(s.Patterns.P2),
		strconv.Itoa(s.Patterns.P3),
		strconv.Itoa(s.Patterns.P4),
		strconv.Itoa(s.Patterns.P5),
		strconv.Itoa(s.Patterns.P6),
		strconv.Itoa(s.Patterns.P7),
		strconv.Itoa(s.Patterns.P8),
		strconv.Itoa(s.Patterns.P9),
		strconv.Itoa(s.Patterns.P10),
	}

	// sensitive (20) -- order guaranteed to match SensitiveAccessColumns()
	for _, v := range s.Sensitive.Values() {
		row = append(row, strconv.Itoa(v))
	}

	row = append(row, severityScore)

	return row, nil
}

// BuildRecord converts a collected session into the JSON output format,
// including a verdict banded against thresholds.
func BuildRecord(sess *session.Session, installFeatures features.InstallFeatures, thresholds verdict.Thresholds) SessionRecord {
	record := SessionRecord{
		SchemaVersion: CurrentSchemaVersion,
		Install:       installFeatures,
		Opensnoop:     (&features.DirCounts{}).ToMap(),
	}

	if sess == nil {
		v := verdict.Evaluate(verdict.Input{Install: installFeatures}, verdict.DefaultRules, thresholds)
		record.Verdict = &v
		return record
	}

	// Read every field through one snapshot rather than reaching into the
	// session directly. The collectors are usually still writing to this
	// session when the output worker gets here (Detector.RouteToSession calls
	// session.AddX with no detector lock held), and SyscallCounts and the TCP
	// aggregator's sets are maps -- an unsynchronised read of those is
	// "fatal error: concurrent map read and map write", which kills the process
	// and loses every in-flight session. See AUDIT.md C2 and
	// docs/fix-c2-buildrecord-race/.
	snap := sess.Snapshot()

	record.SessionID = snap.ID
	record.PackageName = snap.PackageName
	record.ProcessTree = snap.ProcessTree
	record.Timestamp = snapshotTimestamp(snap)
	record.Syscalls = buildSyscallFeatures(snap.SyscallCounts)
	record.TimedOut = snap.TimedOut
	record.Filetop = snap.Filetop
	record.TCP = snap.TCP
	record.Patterns = snap.Patterns
	record.Sensitive = features.BuildSensitiveAccess(snap.Evidence)

	if snap.Opensnoop != nil {
		record.Opensnoop = snap.Opensnoop
	}

	input := verdict.Input{
		Filetop:   record.Filetop,
		Install:   record.Install,
		DirCounts: record.Opensnoop,
		TCP:       record.TCP,
		Syscalls:  record.Syscalls,
		Patterns:  record.Patterns,
		Evidence:  snap.Evidence,
		Derived:   verdict.NewDerived(record.Syscalls, record.Install.DirectDependencies),
	}
	v := verdict.Evaluate(input, verdict.DefaultRules, thresholds)
	record.Verdict = &v

	return record
}

// JSONWriter persists session records as indented JSON files.
type JSONWriter struct {
	outputDir string
}

// NewJSONWriter creates a JSON writer rooted at dir.
func NewJSONWriter(dir string) *JSONWriter {
	return &JSONWriter{outputDir: dir}
}

// Write marshals and writes a session record, returning the absolute path.
func (w *JSONWriter) Write(record SessionRecord) (string, error) {
	if err := os.MkdirAll(w.outputDir, 0o755); err != nil {
		return "", err
	}

	if record.SchemaVersion == "" {
		record.SchemaVersion = CurrentSchemaVersion
	}

	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", err
	}

	filename := fmt.Sprintf("%s_%s.json", sanitizeFilenamePart(record.SessionID), sanitizeFilenamePart(record.PackageName))
	path := filepath.Join(w.outputDir, filename)
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return "", err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	if valErr := MustValidate(absPath); valErr != nil {
		// Re-read warnings individually for per-field logging.
		var top map[string]interface{}
		if jsonErr := json.Unmarshal(payload, &top); jsonErr == nil {
			for _, field := range ValidateRecord(flattenMap(top)) {
				slog.Warn("session record field missing or zero", "field", field, "path", absPath)
			}
		}
	}

	return absPath, nil
}

func normalizeOpensnoop(in map[string]int) map[string]int {
	base := (&features.DirCounts{}).ToMap()
	if in == nil {
		return base
	}

	for k, v := range in {
		base[k] = v
	}

	if v, ok := in["userlib_dir_access"]; ok {
		base["user_dir_access"] = v
	}

	return base
}

// Validate returns warnings for critical missing or zeroed fields.
func Validate(record SessionRecord) []string {
	var warnings []string

	if record.Syscalls.IoOps == 0 {
		warnings = append(warnings, "warning: syscalls.io_ops is 0 (missing syscall tracer data?)")
	}
	if record.Filetop.FileAccessProcesses == 0 {
		warnings = append(warnings, "warning: filetop.file_access_processes is 0 (missing filetop tracer data?)")
	}
	if record.Install.TotalDependencies == 0 {
		warnings = append(warnings, "warning: install.total_dependencies is 0 (missing package-lock/package.json data?)")
	}
	if record.ProcessTree == "" {
		warnings = append(warnings, "warning: process_tree is empty (missing process tracer data?)")
	}

	return warnings
}

func snapshotTimestamp(snap session.Snapshot) time.Time {
	if !snap.EndTime.IsZero() {
		return snap.EndTime
	}

	return snap.StartTime
}

func buildSyscallFeatures(counts map[features.SyscallCategory]int) features.SyscallFeatures {
	if counts == nil {
		return features.SyscallFeatures{}
	}

	return features.SyscallFeatures{
		IoOps:       counts[features.CategoryIO],
		FileOps:     counts[features.CategoryFile],
		NetworkOps:  counts[features.CategoryNetwork],
		TimeOps:     counts[features.CategoryTime],
		SecurityOps: counts[features.CategorySecurity],
		ProcessOps:  counts[features.CategoryProcess],
		UnknownOps:  counts[features.CategoryUnknown],
	}
}

// maxFilenamePart caps each component of a session filename. Most filesystems
// limit a single name to 255 bytes; two capped parts plus the separator and the
// ".json" suffix stay comfortably inside that.
const maxFilenamePart = 100

// sanitizeFilenamePart makes an arbitrary string safe to embed in a filename.
//
// npm package specs are not identifiers: "npm install ./local-dep",
// "@scope/pkg", "file:../thing" and "git+https://host/x.git" are all valid, and
// every one of them contains characters that change the meaning of a path.
// Interpolated raw, they made os.WriteFile target a directory that does not
// exist (losing the session, since the monitor only logs the error) or, for a
// leading "..", resolve outside the output directory entirely.
//
// Characters outside the safe set collapse to "-", and leading/trailing "." and
// "-" are trimmed so the result can never be "", ".", ".." or a hidden file.
// Names already made of safe characters -- which is every package in the
// project's corpus -- are returned unchanged, so existing filenames and the
// substring matching the dataset labeller relies on are preserved.
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
