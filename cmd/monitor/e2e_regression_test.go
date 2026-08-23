package main

// e2e_regression_test.go drives the compiled ./cmd/monitor and
// ./cmd/dataset/labeler binaries against real npm installs of synthetic,
// network-free local packages, as a companion to the many collector- and
// detector-level unit tests scattered across this repository. Those tests
// each pin one fix's own narrow seam in isolation (e.g.
// TestFileMonitorCountsFailedPendingOpensInserts drives one BPF map
// directly); these pin the seam an operator actually depends on: what the
// real binary does, end to end, for a whole install's lifecycle, across
// several of AUDIT.md's fixes at once.
//
// Seam under test: the compiled monitor and labeler binaries' exit codes,
// stdout/stderr, and the session JSON files they read and write -- driven by
// real npm installs of synthetic local packages, never a real registry
// package. That mirrors the existing precedent in
// internal/features/filetop_npm_e2e_test.go's newNpmFixture: real kernel
// events, real npm, no network dependency and no flakiness from an
// unreachable registry.
//
// Every test here requires root (to load BPF) and a working npm; both are
// skipped for otherwise. See docs/bugs-fixed/regression-suite-fixed-bugs/
// for which AUDIT.md finding and which fix each test is pinned against, and
// for the one real, previously-undemonstrated gap this suite closed.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// --- shared build/process helpers -------------------------------------------------

var (
	buildBinOnce sync.Map // module import path -> *buildResult
)

type buildResult struct {
	once sync.Once
	path string
	err  error
}

// buildBinary compiles the given package (by module import path) once per
// test process and returns the path to the resulting binary. Building via
// "go build" from inside a running "go test" process is deliberate: it
// exercises the exact artifact an operator would run, not a reimplementation
// of main() inside the test.
func buildBinary(t *testing.T, importPath, name string) string {
	t.Helper()

	v, _ := buildBinOnce.LoadOrStore(importPath, &buildResult{})
	br := v.(*buildResult)
	br.once.Do(func() {
		dir, err := os.MkdirTemp("", "e2e-bin-*")
		if err != nil {
			br.err = err
			return
		}
		bin := filepath.Join(dir, name)
		cmd := exec.Command("/usr/bin/go", "build", "-o", bin, importPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			br.err = fmt.Errorf("go build %s: %v\n%s", importPath, err, out)
			return
		}
		br.path = bin
	})
	if br.err != nil {
		t.Fatalf("build %s: %v", importPath, br.err)
	}
	return br.path
}

func buildMonitorBinary(t *testing.T) string {
	return buildBinary(t, "github.com/aniruddha/npm-ebpf-monitor/cmd/monitor", "monitor")
}

func buildLabelerBinary(t *testing.T) string {
	return buildBinary(t, "github.com/aniruddha/npm-ebpf-monitor/cmd/dataset/labeler", "labeler")
}

// syncBuffer is a bytes.Buffer safe for the concurrent write (from
// os/exec's own output-copying goroutine) and read (from the polling test
// goroutine) this suite needs while a subprocess is still running.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type monitorProc struct {
	cmd    *exec.Cmd
	stdout *syncBuffer
	stderr *syncBuffer
}

func (mp *monitorProc) output() string {
	return mp.stdout.String() + mp.stderr.String()
}

// startMonitor launches the compiled monitor binary against outputDir and
// waits for its "active" startup line, so callers know every BPF probe
// attached before driving an install against it. A short session timeout
// keeps a failing test's session from lingering past the test itself.
func startMonitor(t *testing.T, outputDir string) *monitorProc {
	t.Helper()

	bin := buildMonitorBinary(t)
	cmd := exec.Command(bin, "-output-dir", outputDir, "-session-timeout", "8s", "-verbose")
	mp := &monitorProc{cmd: cmd, stdout: &syncBuffer{}, stderr: &syncBuffer{}}
	cmd.Stdout = mp.stdout
	cmd.Stderr = mp.stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start monitor: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil && cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for {
		if strings.Contains(mp.output(), "npm-ebpf-monitor active") {
			return mp
		}
		if time.Now().After(deadline) {
			t.Fatalf("monitor did not report its active state within 10s; output so far:\n%s", mp.output())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// stopMonitor sends SIGINT -- the only path to cmd/monitor/main.go's
// shutdown/report block -- and waits for the process to exit, returning its
// exit code. A monitor whose Detector.Shutdown wiring (AUDIT.md H3) is
// broken would hang here instead of closing detector.Completed() and
// letting the output worker finish, so this doubles as a live regression
// guard for that fix, not just a way to read the exit code.
func stopMonitor(t *testing.T, mp *monitorProc) int {
	t.Helper()

	if err := mp.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("signal monitor: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- mp.cmd.Wait() }()

	select {
	case err := <-done:
		if err == nil {
			return 0
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		t.Fatalf("monitor wait: %v", err)
		return -1
	case <-time.After(20 * time.Second):
		_ = mp.cmd.Process.Kill()
		t.Fatalf("monitor did not exit within 20s of SIGINT (Detector.Shutdown wiring, AUDIT.md H3, "+
			"may be broken); output so far:\n%s", mp.output())
		return -1
	}
}

// --- npm fixture helpers -----------------------------------------------------------

// shortTempDir is t.TempDir() with a short, fixed-prefix name instead of one
// derived from the (often long) test name. Used specifically for paths that
// end up embedded in a monitored process's argv: ProcessEvent.Args is a
// fixed 256-byte kernel-side buffer (process_tracer.bpf.c), and this
// project's own long, descriptive test names (by design, per this repo's
// existing convention) can push "npm install --no-audit --no-fund
// <t.TempDir() path>" past that cap well before reaching anything this
// suite is actually testing -- a fixture-construction artifact, not a
// regression in any fix under test here.
func shortTempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "e2e")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// newLocalPackage creates a minimal, network-free npm package fixture. Its
// postinstall is deliberately network-free (this suite tests session
// capture / labeling / exit-code plumbing across the whole program, not
// attack-behaviour detection -- tests/packages/* with real, safe
// attack-simulation scripts exists for that, exercised separately via
// scripts/compare_packages*.sh) but runs for a short, fixed duration via a
// synchronous busy-wait rather than exiting instantly: a postinstall that
// forks, execs, and exits within microseconds leaves the real fork/exec/exit
// event pipeline (ring buffer -> collector -> router -> detector) no real
// chance to attach the child's own exec before its exit is processed, which
// is a timing property of this fixture, not of the fork/exec propagation
// path under test -- confirmed against this project's own captured corpus
// (sessions/npm-*_{ci-secret-grabber,crypto-miner,reverse-shell,env-stealer}-test-*.tgz.json),
// whose postinstall scripts all do enough real synchronous work to reliably
// show a multi-hop process_tree.
func newLocalPackage(t *testing.T, name, version string) string {
	t.Helper()

	dir := shortTempDir(t)
	pkgJSON := fmt.Sprintf(`{"name":%q,"version":%q,"scripts":{"postinstall":"node postinstall.js"}}`, name, version)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	postinstall := `const end = Date.now() + 300;
while (Date.now() < end) { /* keep this process alive briefly, see newLocalPackage's comment */ }
console.log('fixture postinstall ran');
`
	if err := os.WriteFile(filepath.Join(dir, "postinstall.js"), []byte(postinstall), 0o644); err != nil {
		t.Fatalf("write postinstall.js: %v", err)
	}
	return dir
}

// newMaliciousLocalPackage creates a network-free-except-for-loopback npm
// package fixture whose postinstall does the one thing this project's rule
// engine treats as decisive: it reads a credential-shaped path (a file whose
// name ends in "/.ssh/id_rsa", matching features.PathClassSSHPrivateKey) and
// then, strictly afterwards, opens an outbound connection -- the ordered
// read-then-connect shape RuleEXFIL001 (internal/verdict/rules.go) is built
// to catch. The connection target is loopbackPort, a listener this test
// starts itself, so the fixture never depends on the network or on any of
// the tests/packages/* attack-simulation fixtures.
//
// The key file lives under a fixture-private subdirectory of os.TempDir(),
// not a real user's actual ~/.ssh -- PathClass matching is suffix-based (see
// internal/features/pathclass.go) precisely so this works without needing
// $HOME to point anywhere real.
func newMaliciousLocalPackage(t *testing.T, name, version string, loopbackPort int) string {
	t.Helper()

	dir := shortTempDir(t)
	pkgJSON := fmt.Sprintf(`{"name":%q,"version":%q,"scripts":{"postinstall":"node postinstall.js"}}`, name, version)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	postinstall := fmt.Sprintf(`const fs = require('fs');
const net = require('net');
const path = require('path');
const os = require('os');

const sshDir = path.join(os.tmpdir(), 'e2e-exfil-fake-home', '.ssh');
fs.mkdirSync(sshDir, { recursive: true });
const keyPath = path.join(sshDir, 'id_rsa');
fs.writeFileSync(keyPath, 'fake-private-key-for-e2e-test\n');
fs.readFileSync(keyPath, 'utf8');

// Give the read's openat a moment to be picked up off the ring buffer before
// the connect happens, so the two events are seen in the order they really
// occurred in -- see EvidenceCollector.markFirstSeen's own comment on why
// ordering, not just presence, is what RuleEXFIL001 requires.
const end = Date.now() + 200;
while (Date.now() < end) { /* busy-wait, see newLocalPackage's comment */ }

const sock = net.connect(%d, '127.0.0.1', () => {
	sock.end();
	console.log('fixture postinstall ran (malicious e2e)');
});
sock.on('error', () => { /* the test's listener may already be gone by shutdown; irrelevant here */ });
`, loopbackPort)
	if err := os.WriteFile(filepath.Join(dir, "postinstall.js"), []byte(postinstall), 0o644); err != nil {
		t.Fatalf("write postinstall.js: %v", err)
	}
	return dir
}

// npmPack runs "npm pack" in pkgDir and returns the resulting tarball's bare
// filename (e.g. "crypto-miner-test-1.0.0.tgz") -- the same npm-defined
// "<name>-<version>.tgz" convention this project's own captured corpus
// (sessions/npm-*_*.tgz.json) already uses.
func npmPack(t *testing.T, pkgDir string) string {
	t.Helper()

	cmd := exec.Command("npm", "pack", "--silent")
	cmd.Dir = pkgDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("npm pack (dir=%s): %v\n%s", pkgDir, err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	name := strings.TrimSpace(lines[len(lines)-1])
	if name == "" || !strings.HasSuffix(name, ".tgz") {
		t.Fatalf("npm pack (dir=%s): unexpected output: %q", pkgDir, string(out))
	}
	return name
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()

	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

// runNpmInstall runs "npm install <args...>" in dir, bounded to 45s so a
// hung install fails the test instead of hanging the whole suite.
//
// --dangerously-allow-all-scripts is required on npm versions that gate
// lifecycle scripts behind a per-dependency allowScripts approval (npm 12.x
// on this machine): without it, "npm install" of any of this suite's local
// fixtures silently *skips* postinstall entirely ("npm warn install-scripts
// ... blocked because not covered by allowScripts") -- no error, no
// nonzero exit, just a script that never ran, which would otherwise make
// TestMonitorEndToEnd_PathLikeInstallIsCapturedTreeAndSanitized's process-tree
// assertion fail for a reason that has nothing to do with any fix under
// test here. Harmless to pass on older npm versions that predate this flag:
// npm's config parser accepts unrecognized --key flags as ad-hoc config
// rather than erroring.
func runNpmInstall(t *testing.T, dir string, args ...string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// The install target goes immediately after "install", before any flag:
	// parseInstallTarget (internal/session/detector.go) resolves the package
	// as the first non-flag token following "install" in the *captured*
	// argv, which is truncated at a fixed 256 bytes at the kernel boundary
	// (ProcessEvent.Args, process_tracer.bpf.c) -- putting the target first
	// guarantees it lands well inside that budget regardless of how many
	// flags follow it.
	cmdArgs := append([]string{"install"}, args...)
	cmdArgs = append(cmdArgs, "--no-audit", "--no-fund", "--dangerously-allow-all-scripts")
	cmd := exec.CommandContext(ctx, "npm", cmdArgs...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("npm %v (dir=%s): %v\n%s", cmdArgs, dir, err, out)
	}
}

func requireRootAndNpm(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
}

func readSessionJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var record map[string]interface{}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return record
}

// waitForSessionWithPackageName polls dir until a session JSON whose
// package_name field equals wantPkg appears, and returns its path and
// decoded record.
//
// The monitor watches the whole machine for npm activity, not just this
// test's own subprocess tree -- when the full repository suite runs, other
// packages' own real-npm-install tests (e.g.
// internal/features/filetop_npm_e2e_test.go's "npm install ./localdep")
// can run concurrently and be captured as extra, unrelated sessions in the
// same outputDir. Matching on this test's own distinctive package name,
// rather than assuming "the first/only file that appears is mine" or "the
// file count is exactly N", is what makes these tests correct under that
// real ambient concurrency instead of merely correct in isolation.
func waitForSessionWithPackageName(t *testing.T, dir, wantPkg string, timeout time.Duration) (string, map[string]interface{}) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			record := readSessionJSON(t, path)
			if pkg, _ := record["package_name"].(string); pkg == wantPkg {
				return path, record
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no session with package_name %q appeared in %s within %s", wantPkg, dir, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// --- tests ---------------------------------------------------------------------

// TestMonitorEndToEnd_PathLikeInstallIsCapturedTreeAndSanitized drives the
// real monitor binary against a real npm install whose target is a local
// filesystem path (guaranteed to contain '/'), the same shape of install
// spec that silently lost sessions before the output-filename-sanitization
// fix (docs/bugs-fixed/fix-output-filename-sanitization/).
//
// It also, as a side effect of using a package with a real postinstall
// script, exercises the full real fork/exec propagation chain fixed by
// docs/bugs-fixed/fix-processtracer-fork-load/ (ProcessTracer must load at
// all on this kernel) and docs/bugs-fixed/fix-fork-tgid-lookup/ (the child
// node process's own exec must be attached to the right session) -- through
// real npm and real node, not the synthetic C fixture or the /proc-walking
// substitute those fixes' own tests used. See
// docs/bugs-fixed/fix-fork-tgid-lookup/07-findings-not-fixed.md, finding B,
// which named exactly this gap as unclosed.
//
// Finally, a clean run reaching exit 0 depends on Detector.Shutdown actually
// closing detector.Completed() (AUDIT.md H3) -- if that wiring regressed,
// stopMonitor's own 20s deadline would fail this test with a clear message
// rather than a silent hang.
//
// Assertions here deliberately do not assume this session is the only one
// captured, or the first/only file in outputDir: see
// waitForSessionWithPackageName's own comment for why (real ambient npm
// activity from other packages' tests, when the full suite runs together).
func TestMonitorEndToEnd_PathLikeInstallIsCapturedTreeAndSanitized(t *testing.T) {
	requireRootAndNpm(t)

	outputDir := t.TempDir()
	mp := startMonitor(t, outputDir)

	pkgDir := newLocalPackage(t, "e2e-path-spec-test", "1.0.0") // absolute path -- contains '/'
	projectDir := t.TempDir()
	runNpmInstall(t, projectDir, pkgDir)

	path, record := waitForSessionWithPackageName(t, outputDir, pkgDir, 15*time.Second)

	exitCode := stopMonitor(t, mp)
	if exitCode != 0 {
		t.Fatalf("monitor exit code = %d, want 0\noutput:\n%s", exitCode, mp.output())
	}

	// The filename itself must not contain the raw path's '/' -- the fix
	// under test. If it did, the very fact that waitForSessionWithPackageName
	// found a *.json file inside outputDir (not one written to some other
	// directory entirely, or a failed write) already proves this at a
	// coarser grain; this asserts it explicitly too.
	if strings.ContainsRune(filepath.Base(path), '/') {
		t.Errorf("session filename %q still contains '/'", filepath.Base(path))
	}

	// process_tree starts as exactly "npm(<pid>)" (session.go) and only grows
	// when a tracked child's own exec is attached. Anything beyond that bare
	// form is direct evidence that the postinstall's node child process was
	// correctly propagated end to end through the real kernel, ProcessTracer,
	// and the fork-tgid fix -- not asserting the exact tree shape, since the
	// PID and comm are non-deterministic, only that propagation happened at
	// all.
	tree, _ := record["process_tree"].(string)
	if !strings.Contains(tree, "->") {
		t.Errorf("process_tree = %q, want it to include at least one propagated child (\"->\"); "+
			"the postinstall's node child process was not attached to this session", tree)
	}
}

// TestMonitorEndToEnd_BenignAndMaliciousFixturesAreLabeledCorrectly chains
// the real monitor and labeler binaries -- capture, then label -- against
// one benign and one malicious synthetic fixture named after real entries in
// internal/dataset's ground-truth table, closing the C4 fix
// (docs/bugs-fixed/fix-c4-ground-truth-labels/) at the level that actually
// matters for the training set: a session file the real monitor wrote,
// labeled by the real labeler binary, not a synthetic record.
//
// Expected labels are literal, independently-stated values (matching the
// same non-tautological style as internal/dataset/labels_test.go), not
// derived by calling dataset.Lookup from this test -- the point is to prove
// the whole pipeline preserves the package name correctly from capture
// through to labeling, not to re-test Lookup's own table.
func TestMonitorEndToEnd_BenignAndMaliciousFixturesAreLabeledCorrectly(t *testing.T) {
	requireRootAndNpm(t)

	outputDir := t.TempDir()
	mp := startMonitor(t, outputDir)

	fixtures := []struct {
		name      string
		wantLabel float64 // json.Unmarshal decodes numbers as float64
	}{
		{name: "benign-test", wantLabel: 0},
		{name: "crypto-miner-test", wantLabel: 1},
	}

	for _, f := range fixtures {
		pkgDir := newLocalPackage(t, f.name, "1.0.0")
		tgz := npmPack(t, pkgDir)
		projectDir := t.TempDir()
		copyFile(t, filepath.Join(pkgDir, tgz), filepath.Join(projectDir, tgz))
		runNpmInstall(t, projectDir, tgz) // bare filename arg, cwd=projectDir -- matches this project's real captured corpus
	}

	// Poll for each fixture's own exact package_name individually, rather
	// than "at least len(fixtures) files total": real ambient npm activity
	// from other packages' tests, when the full suite runs together, could
	// otherwise satisfy an aggregate file-count check with a mix of one real
	// fixture and one unrelated session, leaving this test looking for a
	// fixture that never actually completed capture. See
	// waitForSessionWithPackageName's own comment for the full reasoning.
	paths := make([]string, len(fixtures))
	for i, f := range fixtures {
		wantPkg := f.name + "-1.0.0.tgz"
		path, _ := waitForSessionWithPackageName(t, outputDir, wantPkg, 20*time.Second)
		paths[i] = path
	}

	exitCode := stopMonitor(t, mp)
	if exitCode != 0 {
		t.Fatalf("monitor exit code = %d, want 0\noutput:\n%s", exitCode, mp.output())
	}

	labelerBin := buildLabelerBinary(t)
	cmd := exec.Command(labelerBin, "-dir", outputDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("labeler -dir %s: %v\n%s", outputDir, err, out)
	}

	for i, f := range fixtures {
		// Re-read from disk: the labeler rewrites the file in place.
		labeled := readSessionJSON(t, paths[i])

		got, ok := labeled["label"].(float64)
		if !ok {
			t.Errorf("fixture %q: session file has no numeric \"label\" field after labeling; record=%v", f.name, labeled)
			continue
		}
		if got != f.wantLabel {
			t.Errorf("fixture %q: label = %v, want %v", f.name, got, f.wantLabel)
		}
	}
}

// TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert drives the
// real monitor binary against a real npm install whose postinstall script
// reads a credential-shaped path and then connects outbound, the ordered
// shape internal/verdict's decisive RuleEXFIL001 exists to catch. It is the
// first end-to-end test in this suite to close the loop across every stage
// of the verdict engine at once, through real kernel events rather than
// hand-built verdict.Input values: the Stage 1 kernel change that carries a
// file's path through struct pending_open (bpf/file_monitor.bpf.c) feeds
// features.EvidenceCollector's path classification (internal/features/
// pathclass.go), which internal/session.Session hydrates under its own
// lock and internal/verdict.Evaluate consumes to produce a decisive
// "malicious" verdict, which internal/output writes into the session JSON
// and cmd/monitor's output worker turns into a live [ALERT] line on stdout.
//
// The outbound connection targets a listener this test starts itself on
// 127.0.0.1, not a real network endpoint or one of tests/packages/*'s
// existing attack-simulation fixtures -- see newMaliciousLocalPackage's own
// comment for why that keeps this test free of any network or fixture
// dependency while still exercising a real TCPEvent from a real connect().
//
// See docs/new-features/001-verdict-scoring-engine/ for this rule and the
// data that calibrated it.
func TestMonitorEndToEnd_MaliciousInstallGetsDecisiveVerdictAndAlert(t *testing.T) {
	requireRootAndNpm(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start loopback listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	loopbackPort := ln.Addr().(*net.TCPAddr).Port

	outputDir := t.TempDir()
	mp := startMonitor(t, outputDir)

	pkgDir := newMaliciousLocalPackage(t, "e2e-exfil-test", "1.0.0", loopbackPort)
	tgz := npmPack(t, pkgDir)
	projectDir := t.TempDir()
	copyFile(t, filepath.Join(pkgDir, tgz), filepath.Join(projectDir, tgz))
	runNpmInstall(t, projectDir, tgz) // bare filename arg, cwd=projectDir -- matches this project's real captured corpus

	wantPkg := "e2e-exfil-test-1.0.0.tgz"
	path, record := waitForSessionWithPackageName(t, outputDir, wantPkg, 20*time.Second)

	exitCode := stopMonitor(t, mp)
	if exitCode != 0 {
		t.Fatalf("monitor exit code = %d, want 0\noutput:\n%s", exitCode, mp.output())
	}

	if sv, _ := record["schema_version"].(string); sv != "1.1.0" {
		t.Errorf("session %s: schema_version = %q, want \"1.1.0\"", path, sv)
	}

	verdictRaw, ok := record["verdict"].(map[string]interface{})
	if !ok {
		t.Fatalf("session %s has no \"verdict\" object; record=%v", path, record)
	}
	if level, _ := verdictRaw["level"].(string); level != "malicious" {
		t.Errorf("session %s: verdict.level = %q, want \"malicious\"; verdict=%v", path, level, verdictRaw)
	}

	findings, _ := verdictRaw["findings"].([]interface{})
	foundExfil := false
	for _, f := range findings {
		fm, ok := f.(map[string]interface{})
		if !ok {
			continue
		}
		if id, _ := fm["rule_id"].(string); id == "EXFIL-001" {
			foundExfil = true
			break
		}
	}
	if !foundExfil {
		t.Errorf("session %s: verdict.findings does not contain EXFIL-001; findings=%v\nmonitor output:\n%s", path, findings, mp.output())
	}

	out := mp.output()
	if !strings.Contains(out, "[ALERT]") || !strings.Contains(out, "MALICIOUS") {
		t.Errorf("monitor stdout/stderr does not contain a malicious alert line; output:\n%s", out)
	}
	if !strings.Contains(out, "e2e-exfil-test") {
		t.Errorf("monitor's alert line does not name the offending package; output:\n%s", out)
	}
}

// TestMonitorEndToEnd_ExitsNonZeroAndReportsLossWhenOutputCannotBeWritten
// closes a previously-undemonstrated verification gap named explicitly in
// docs/bugs-fixed/fix-silent-write-failures/07-findings-not-fixed.md, finding
// A: "the process exit status was not verified end to end" because, at the
// time, the sudo grant available only covered the go binary itself, and a
// root-owned monitor process could not be signalled from an unprivileged
// session. Running entirely inside a root-owned `go test` process removes
// that obstacle: this test's own process is root, so it can signal a
// root-owned child it spawned directly, with no separate terminal needed.
func TestMonitorEndToEnd_ExitsNonZeroAndReportsLossWhenOutputCannotBeWritten(t *testing.T) {
	requireRootAndNpm(t)

	// A directory whose parent path component is a regular file: os.MkdirAll
	// (inside output.JSONWriter.Write) fails with ENOTDIR for every write.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("create blocker file: %v", err)
	}
	outputDir := filepath.Join(blocker, "sessions")

	mp := startMonitor(t, outputDir)

	pkgDir := newLocalPackage(t, "e2e-blocked-write-test", "1.0.0")
	projectDir := t.TempDir()
	runNpmInstall(t, projectDir, pkgDir)

	// No file can ever appear in outputDir (every write fails), so there is
	// nothing to poll for. Give the event pipeline -- ring buffer -> collector
	// -> router -> detector.handleExit -> output worker's failed Write -- time
	// to run its course before signalling shutdown. 1500ms matches the drain
	// wait internal/features/filetop_npm_e2e_test.go already uses for the same
	// kind of asynchronous, unobservable-from-outside completion.
	time.Sleep(1500 * time.Millisecond)

	exitCode := stopMonitor(t, mp)

	if exitCode != 1 {
		t.Fatalf("monitor exit code = %d, want 1 (a session was lost); output:\n%s", exitCode, mp.output())
	}
	// Exact count deliberately not asserted: outputDir is blocked for every
	// write, so if real ambient npm activity from another package's test
	// also lands a session on this monitor while it runs (see
	// waitForSessionWithPackageName's comment), that session is lost too,
	// making a legitimate "LOST 2 of 2" as valid evidence of the fix as
	// "LOST 1 of 1" -- only the shape of the report, and that at least one
	// session was counted lost, matters here.
	if !lostReportPattern.MatchString(mp.output()) {
		t.Errorf("output does not contain a loss report matching %q; output:\n%s", lostReportPattern, mp.output())
	}
}

var lostReportPattern = regexp.MustCompile(`LOST [1-9]\d* of [1-9]\d* session\(s\)`)
