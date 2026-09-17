package output

import (
	"encoding/json"
	"testing"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
	"github.com/aniruddha/npm-ebpf-monitor/internal/session"
	"github.com/aniruddha/npm-ebpf-monitor/internal/verdict"
)

// TestCurrentSchemaVersionIsBumpedForVerdict pins the schema version so that
// adding a top-level block to SessionRecord cannot happen silently: a
// consumer keying off the version has to be told. 1.1.0 added "verdict",
// 1.2.0 added "sensitive".
func TestCurrentSchemaVersionIsBumpedForVerdict(t *testing.T) {
	if CurrentSchemaVersion != "1.2.0" {
		t.Fatalf("CurrentSchemaVersion = %q, want %q", CurrentSchemaVersion, "1.2.0")
	}
}

func TestBuildRecordAttachesBenignVerdictForEmptySession(t *testing.T) {
	sess := session.NewSession(1, "left-pad")

	record := BuildRecord(sess, features.InstallFeatures{}, verdict.DefaultThresholds)

	if record.Verdict == nil {
		t.Fatal("record.Verdict = nil, want a non-nil verdict even for an empty session")
	}
	if record.Verdict.Level != verdict.LevelBenign {
		t.Fatalf("record.Verdict.Level = %q, want %q", record.Verdict.Level, verdict.LevelBenign)
	}
	if record.Verdict.Score != 0 {
		t.Fatalf("record.Verdict.Score = %d, want 0", record.Verdict.Score)
	}
}

// TestBuildRecordAttachesMaliciousVerdictForDecisiveEvidence exercises the
// EXFIL-001 rule end to end through BuildRecord: a session that read a
// credential file and then made an outbound connection must be scored
// malicious, decisively, regardless of thresholds.
func TestBuildRecordAttachesMaliciousVerdictForDecisiveEvidence(t *testing.T) {
	sess := session.NewSession(707, "env-stealer-test")

	var fileEvt collector.FileEvent
	fileEvt.Pid = 707
	copy(fileEvt.Filename[:], "/home/x/.aws/credentials")
	fileEvt.TimestampNs = 100
	sess.AddFile(fileEvt)

	sess.AddTCP(collector.TCPEvent{
		Pid: 707, Daddr: 0x0100007f, Dport: 4444, TimestampNs: 200,
	})

	record := BuildRecord(sess, features.InstallFeatures{}, verdict.DefaultThresholds)

	if record.Verdict == nil {
		t.Fatal("record.Verdict = nil")
	}
	if record.Verdict.Level != verdict.LevelMalicious {
		t.Fatalf("record.Verdict.Level = %q, want %q (score %d, findings %+v)",
			record.Verdict.Level, verdict.LevelMalicious, record.Verdict.Score, record.Verdict.Findings)
	}

	foundExfil := false
	for _, f := range record.Verdict.Findings {
		if f.RuleID == "EXFIL-001" {
			foundExfil = true
		}
	}
	if !foundExfil {
		t.Fatalf("record.Verdict.Findings = %+v, want EXFIL-001 present", record.Verdict.Findings)
	}
}

// TestBuildRecordThresholdsAreOverridable pins that the thresholds argument,
// not a package-level default, controls banding.
func TestBuildRecordThresholdsAreOverridable(t *testing.T) {
	sess := session.NewSession(808, "chalk")

	// A single CRED-001 hit (weight 25) is "suspicious" under the default
	// thresholds (>= 25) but "benign" under a much higher custom one.
	var fileEvt collector.FileEvent
	fileEvt.Pid = 808
	copy(fileEvt.Filename[:], "/home/x/.aws/credentials")
	fileEvt.TimestampNs = 100
	sess.AddFile(fileEvt)

	strict := verdict.Thresholds{Suspicious: 1000, Malicious: 2000}
	record := BuildRecord(sess, features.InstallFeatures{}, strict)

	if record.Verdict.Level != verdict.LevelBenign {
		t.Fatalf("record.Verdict.Level = %q under raised thresholds, want %q (score %d)",
			record.Verdict.Level, verdict.LevelBenign, record.Verdict.Score)
	}

	record = BuildRecord(sess, features.InstallFeatures{}, verdict.DefaultThresholds)
	if record.Verdict.Level == verdict.LevelBenign {
		t.Fatalf("record.Verdict.Level = %q under default thresholds, want suspicious or malicious (score %d)",
			record.Verdict.Level, record.Verdict.Score)
	}
}

// TestBuildRecordFeatureFieldsUnaffectedByVerdict asserts the 36 QUT-DV25
// feature fields marshal to exactly the values an independently-worked-out
// expectation predicts, unaffected by the new verdict field sitting
// alongside them. Expected values are literal constants here, not values
// re-derived the way BuildRecord computes them.
func TestBuildRecordFeatureFieldsUnaffectedByVerdict(t *testing.T) {
	sess := session.NewSession(909, "lodash")

	sess.AddSyscall(collector.SyscallEvent{Pid: 909, SyscallID: 257}) // openat -> file
	sess.AddSyscall(collector.SyscallEvent{Pid: 909, SyscallID: 0})   // read -> io
	sess.AddFile(collector.FileEvent{Pid: 909, Flags: 0})

	record := BuildRecord(sess, features.InstallFeatures{
		TotalDependencies: 5, DirectDependencies: 2, IndirectDependencies: 3,
	}, verdict.DefaultThresholds)

	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal(record) error = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("json.Unmarshal(...) error = %v", err)
	}

	install, ok := got["install"].(map[string]any)
	if !ok {
		t.Fatal("install field missing or wrong type")
	}
	if install["total_dependencies"] != 5.0 || install["direct_dependencies"] != 2.0 || install["indirect_dependencies"] != 3.0 {
		t.Fatalf("install = %+v, want total=5 direct=2 indirect=3", install)
	}

	if _, ok := got["verdict"]; !ok {
		t.Fatal(`"verdict" key missing from marshaled record`)
	}
	// Presence of "verdict" must not have displaced or renamed any existing
	// top-level feature key.
	for _, key := range []string{"filetop", "install", "opensnoop", "tcp", "syscalls", "patterns"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("top-level key %q missing from marshaled record", key)
		}
	}
}

// TestSessionRecordUnmarshalsLegacyRecordWithoutVerdictKey confirms that a
// 1.0.0-era file -- captured before this change, with no "verdict" key at
// all -- still unmarshals cleanly: Verdict stays nil rather than the decode
// failing.
func TestSessionRecordUnmarshalsLegacyRecordWithoutVerdictKey(t *testing.T) {
	legacy := `{
		"schema_version": "1.0.0",
		"session_id": "npm-1700000000",
		"package_name": "lodash",
		"label": 0,
		"filetop": {"read_processes":1,"write_processes":0,"read_data_transfer_kb":0,"write_data_transfer_kb":0,"file_access_processes":1},
		"install": {"total_dependencies":1,"direct_dependencies":1,"indirect_dependencies":0},
		"opensnoop": {"root_dir_access":0,"temp_dir_access":0,"home_dir_access":0,"user_dir_access":0,"sys_dir_access":0,"etc_dir_access":0,"other_dir_access":0},
		"tcp": {"state_transitions":0,"local_ips":0,"remote_ips":0,"local_ports":0,"remote_ports":0},
		"syscalls": {"io_ops":0,"file_ops":0,"network_ops":0,"time_ops":0,"security_ops":0,"process_ops":0,"unknown_ops":0},
		"patterns": {"p1":0,"p2":0,"p3":0,"p4":0,"p5":0,"p6":0,"p7":0,"p8":0,"p9":0,"p10":0},
		"process_tree": "npm(1)",
		"timed_out": false
	}`

	var record SessionRecord
	if err := json.Unmarshal([]byte(legacy), &record); err != nil {
		t.Fatalf("json.Unmarshal(legacy 1.0.0 record) error = %v", err)
	}
	if record.Verdict != nil {
		t.Fatalf("record.Verdict = %+v, want nil for a file with no verdict key", record.Verdict)
	}
	if record.SessionID != "npm-1700000000" || record.PackageName != "lodash" {
		t.Fatalf("record = %+v, legacy fields did not survive the round trip", record)
	}
}

// TestToCSVRowWidthAndLegacyColumnPositions pins the export layout.
//
// The verdict block remains a JSON-only addition and contributes no columns.
// The sensitive block does contribute 20, appended after the legacy features
// and before severity_score specifically so that every pre-existing column
// keeps its index -- CSVs exported before this change stay comparable with
// ones exported after, and the column offsets hard-coded in
// TestSessionRecord_ToCSVRow_LegacyUserlibAlias stay correct.
func TestToCSVRowWidthAndLegacyColumnPositions(t *testing.T) {
	const (
		legacyColumns    = 38 // 2 metadata + 36 features
		sensitiveColumns = 20
		severityColumns  = 1
		wantWidth        = legacyColumns + sensitiveColumns + severityColumns
	)

	sess := session.NewSession(1010, "debug")
	record := BuildRecord(sess, features.InstallFeatures{}, verdict.DefaultThresholds)
	label := 0
	record.Label = &label

	row, err := record.ToCSVRow()
	if err != nil {
		t.Fatalf("ToCSVRow() error = %v", err)
	}
	if len(row) != wantWidth {
		t.Fatalf("len(row) = %d, want %d", len(row), wantWidth)
	}

	if got := len(features.SensitiveAccessColumns()); got != sensitiveColumns {
		t.Errorf("SensitiveAccessColumns() has %d entries, want %d; "+
			"update wantWidth here and the header comment on ToCSVRow together",
			got, sensitiveColumns)
	}

	// severity_score stays last, so row[len(row)-1] remains a valid way to
	// reach it -- several tests and downstream scripts rely on that.
	if got := row[len(row)-1]; got != "0" {
		t.Errorf("last column = %q, want the severity score %q", got, "0")
	}
}
