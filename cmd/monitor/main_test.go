package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
	"github.com/aniruddha/npm-ebpf-monitor/internal/output"
	"github.com/aniruddha/npm-ebpf-monitor/internal/session"
	"github.com/aniruddha/npm-ebpf-monitor/internal/verdict"
)

func TestLoadInstallFeaturesUsesSessionCwd(t *testing.T) {
	dirOne := t.TempDir()
	dirTwo := t.TempDir()

	writeTestFile(t, filepath.Join(dirOne, "package.json"), `{
  "dependencies": {
    "lodash": "^4.17.21"
  }
}`)
	writeTestFile(t, filepath.Join(dirOne, "package-lock.json"), `{
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {},
    "once": {}
  }
}`)

	writeTestFile(t, filepath.Join(dirTwo, "package.json"), `{
  "dependencies": {
    "axios": "^1.0.0",
    "follow-redirects": "^1.15.0"
  }
}`)
	writeTestFile(t, filepath.Join(dirTwo, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/axios": {},
    "node_modules/follow-redirects": {},
    "node_modules/form-data": {},
    "node_modules/proxy-from-env": {}
  }
}`)

	gotOne, err := loadInstallFeatures(&session.Session{Cwd: dirOne})
	if err != nil {
		t.Fatalf("loadInstallFeatures(dirOne) error = %v", err)
	}
	gotTwo, err := loadInstallFeatures(&session.Session{Cwd: dirTwo})
	if err != nil {
		t.Fatalf("loadInstallFeatures(dirTwo) error = %v", err)
	}

	wantOne := features.InstallFeatures{
		TotalDependencies:    2,
		DirectDependencies:   1,
		IndirectDependencies: 1,
	}
	wantTwo := features.InstallFeatures{
		TotalDependencies:    4,
		DirectDependencies:   2,
		IndirectDependencies: 2,
	}

	if gotOne != wantOne {
		t.Fatalf("loadInstallFeatures(dirOne) = %+v, want %+v", gotOne, wantOne)
	}
	if gotTwo != wantTwo {
		t.Fatalf("loadInstallFeatures(dirTwo) = %+v, want %+v", gotTwo, wantTwo)
	}
}

func TestLoadInstallFeaturesMissingCwd(t *testing.T) {
	got, err := loadInstallFeatures(&session.Session{})
	if err != nil {
		t.Fatalf("loadInstallFeatures(empty cwd) error = %v, want nil", err)
	}
	if got != (features.InstallFeatures{}) {
		t.Fatalf("loadInstallFeatures(empty cwd) = %+v, want zero value", got)
	}
}

func writeTestFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

// newFailingWriter returns a JSONWriter whose every Write fails, by pointing it
// at a directory path whose parent is a regular file. os.MkdirAll then fails
// with ENOTDIR.
//
// This particular way of forcing a failure is deliberate: the alternative -- a
// read-only output directory -- does not fail when the test runs as root, and
// this package's suite is run under sudo so the eBPF tests can load.
func newFailingWriter(t *testing.T) *output.JSONWriter {
	t.Helper()

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("create blocker file: %v", err)
	}

	return output.NewJSONWriter(filepath.Join(blocker, "sessions"))
}

// feedSessions returns a closed channel carrying n completed sessions.
func feedSessions(n int) <-chan *session.Session {
	ch := make(chan *session.Session, n)
	for i := 0; i < n; i++ {
		ch <- &session.Session{
			ID:          "npm-" + strconv.Itoa(1787400000+i),
			PackageName: "lodash",
		}
	}
	close(ch)
	return ch
}

// TestRunOutputWorkerReportsWriteOutcomes asserts that the output worker counts
// the sessions it persisted and the sessions it could not.
//
// Before this change the worker returned nothing at all: a failed write was
// logged and the loop moved on, so a capture run could discard an arbitrary
// number of sessions and still finish looking like a success. Counting the
// failures is what makes the loss visible.
func TestRunOutputWorkerReportsWriteOutcomes(t *testing.T) {
	tests := []struct {
		name        string
		sessions    int
		writer      func(*testing.T) *output.JSONWriter
		wantWritten int
		wantFailed  int
	}{
		{
			name:        "all writes succeed",
			sessions:    3,
			writer:      func(t *testing.T) *output.JSONWriter { return output.NewJSONWriter(t.TempDir()) },
			wantWritten: 3,
			wantFailed:  0,
		},
		{
			name:        "all writes fail",
			sessions:    3,
			writer:      newFailingWriter,
			wantWritten: 0,
			wantFailed:  3,
		},
		{
			name:        "no sessions at all",
			sessions:    0,
			writer:      func(t *testing.T) *output.JSONWriter { return output.NewJSONWriter(t.TempDir()) },
			wantWritten: 0,
			wantFailed:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats := runOutputWorker(feedSessions(tt.sessions), tt.writer(t), false, verdict.DefaultThresholds, func(output.SessionRecord) {})

			if stats.written != tt.wantWritten {
				t.Errorf("written = %d, want %d", stats.written, tt.wantWritten)
			}
			if stats.failed != tt.wantFailed {
				t.Errorf("failed = %d, want %d", stats.failed, tt.wantFailed)
			}
		})
	}
}

// TestRunOutputWorkerAlertsOnlyForMaliciousVerdict pins the live-alert seam:
// the worker calls alert exactly once, for the session whose verdict bands
// malicious, and never for a session that stays benign.
func TestRunOutputWorkerAlertsOnlyForMaliciousVerdict(t *testing.T) {
	malicious := session.NewSession(1, "env-stealer-test")
	var fileEvt collector.FileEvent
	fileEvt.Pid = 1
	copy(fileEvt.Filename[:], "/home/x/.aws/credentials")
	fileEvt.TimestampNs = 100
	malicious.AddFile(fileEvt)
	malicious.AddTCP(collector.TCPEvent{Pid: 1, Daddr: 0x0100007f, Dport: 4444, TimestampNs: 200})

	benign := session.NewSession(2, "lodash")

	ch := make(chan *session.Session, 2)
	ch <- malicious
	ch <- benign
	close(ch)

	var alerted []output.SessionRecord
	stats := runOutputWorker(ch, output.NewJSONWriter(t.TempDir()), false, verdict.DefaultThresholds,
		func(r output.SessionRecord) { alerted = append(alerted, r) })

	if stats.written != 2 {
		t.Fatalf("stats.written = %d, want 2", stats.written)
	}
	if len(alerted) != 1 {
		t.Fatalf("alert called %d times, want exactly 1; alerted = %+v", len(alerted), alerted)
	}
	if alerted[0].PackageName != "env-stealer-test" {
		t.Fatalf("alerted for package %q, want %q", alerted[0].PackageName, "env-stealer-test")
	}
}

// TestExitCodeForOutputFailsWhenSessionsWereLost pins the exit status the
// monitor reports on shutdown.
//
// A capture run is typically driven by a script. Logging a lost session is not
// enough for that caller to notice; the process must exit non-zero so the run
// stops rather than silently producing an incomplete corpus.
func TestExitCodeForOutputFailsWhenSessionsWereLost(t *testing.T) {
	tests := []struct {
		name  string
		stats outputStats
		want  int
	}{
		{name: "nothing written, nothing failed", stats: outputStats{}, want: 0},
		{name: "everything written", stats: outputStats{written: 12}, want: 0},
		{name: "one session lost", stats: outputStats{written: 11, failed: 1}, want: 1},
		{name: "everything lost", stats: outputStats{failed: 12}, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeForOutput(tt.stats); got != tt.want {
				t.Errorf("exitCodeForOutput(%+v) = %d, want %d", tt.stats, got, tt.want)
			}
		})
	}
}
