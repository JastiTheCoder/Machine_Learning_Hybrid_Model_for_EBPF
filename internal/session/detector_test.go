package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
)

// startDetectorPipeline runs the same two goroutines cmd/monitor/main.go runs
// in production -- Router.Run (event delivery) and Detector.Shutdown (closes
// Completed() on cancellation) -- and returns a channel that closes once both
// have exited.
//
// This replaces the removed Detector.Run(), which used to bundle both jobs
// into one method that no production code ever called (AUDIT.md H3):
// production has always wired Router.Run directly to the real collector
// channels, calling HandleProcess/RouteToSession itself, while Run()'s own
// event channels were fed only by Submit*, which nothing but this test file
// ever invoked. Every test below now drives the detector through the same
// Router-based path production uses, with channel capacities matching the
// real collectors' own buffer sizes (process: 1024, others: 4096).
func startDetectorPipeline(router *Router, detector *Detector, ctx context.Context) <-chan struct{} {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		router.Run(ctx)
	}()
	go func() {
		defer wg.Done()
		detector.Shutdown(ctx)
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()
	return done
}

func TestDetector_NpmInstallLifecycle(t *testing.T) {
	detector := NewDetector(0)
	detector.cwdResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "/tmp/project-lodash", nil
		}
		return "", errors.New("unexpected pid")
	}
	detector.cmdlineResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "bash", nil
		}
		return "", errors.New("unexpected pid")
	}

	procCh := make(chan collector.ProcessEvent, 1024)
	sysCh := make(chan collector.SyscallEvent, 4096)
	fileCh := make(chan collector.FileEvent, 4096)
	tcpCh := make(chan collector.TCPEvent, 4096)
	router := NewRouter(detector, procCh, sysCh, fileCh, tcpCh, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := startDetectorPipeline(router, detector, ctx)

	procCh <- collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("bash"),
		Args:      fixedSlotArgs("npm", "install", "lodash"),
		EventType: processEventExec,
	}
	procCh <- collector.ProcessEvent{
		Pid:       101,
		Ppid:      100,
		Comm:      fixedComm("node"),
		EventType: processEventFork,
	}
	procCh <- collector.ProcessEvent{
		Pid:       101,
		Ppid:      100,
		Comm:      fixedComm("node"),
		Args:      fixedArgs("node worker.js"),
		EventType: processEventExec,
	}
	sysCh <- collector.SyscallEvent{
		Pid:       101,
		SyscallID: 257,
	}
	fileCh <- collector.FileEvent{
		Pid:         101,
		DirCategory: uint8(collector.DirHome),
		Flags:       uint32(syscall.O_RDONLY),
	}
	tcpCh <- collector.TCPEvent{
		Pid:      101,
		Saddr:    1,
		Daddr:    2,
		Sport:    3000,
		Dport:    443,
		OldState: 1,
		NewState: 2,
	}
	procCh <- collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("npm"),
		EventType: processEventExit,
	}

	select {
	case session := <-detector.Completed():
		t.Fatalf("Completed() returned early session: %+v", session)
	case <-time.After(100 * time.Millisecond):
	}

	procCh <- collector.ProcessEvent{
		Pid:       101,
		Comm:      fixedComm("node"),
		EventType: processEventExit,
	}

	var session *Session
	select {
	case session = <-detector.Completed():
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for completed session")
	}

	if session == nil {
		t.Fatal("Completed() returned nil session")
	}
	if !strings.HasPrefix(session.ID, "npm-") {
		t.Fatalf("session.ID = %q, want prefix %q", session.ID, "npm-")
	}
	if session.NpmPID != 100 {
		t.Fatalf("session.NpmPID = %d, want 100", session.NpmPID)
	}
	if session.PackageName != "lodash" {
		t.Fatalf("session.PackageName = %q, want %q", session.PackageName, "lodash")
	}
	if session.Cwd != "/tmp/project-lodash" {
		t.Fatalf("session.Cwd = %q, want %q", session.Cwd, "/tmp/project-lodash")
	}
	if !session.ChildPIDs[101] {
		t.Fatal("ChildPIDs missing child pid 101")
	}
	if session.State != SessionComplete {
		t.Fatalf("session.State = %q, want %q", session.State, SessionComplete)
	}
	if got := session.SyscallCounts[features.CategoryFile]; got != 1 {
		t.Fatalf("session.SyscallCounts[CategoryFile] = %d, want 1", got)
	}
	if session.DirCounts.Home != 1 {
		t.Fatalf("session.DirCounts.Home = %d, want 1", session.DirCounts.Home)
	}
	if session.FiletopAgg.Snapshot().FileAccessProcesses != 1 {
		t.Fatalf("FileAccessProcesses = %d, want 1", session.FiletopAgg.Snapshot().FileAccessProcesses)
	}
	if session.TCPAgg.Counts().StateTransitions != 1 {
		t.Fatalf("StateTransitions = %d, want 1", session.TCPAgg.Counts().StateTransitions)
	}

	detector.mu.RLock()
	_, exists := detector.activeSessions[100]
	detector.mu.RUnlock()
	if exists {
		t.Fatal("activeSessions still contains pid 100 after completion")
	}

	cancel()
	waitForDetectorExit(t, done)
}

func TestDetector_ConcurrentSessionCwds(t *testing.T) {
	detector := NewDetector(0)
	detector.cwdResolver = func(pid uint32) (string, error) {
		switch pid {
		case 100:
			return "/tmp/project-lodash", nil
		case 200:
			return "/tmp/project-axios", nil
		default:
			return "", errors.New("unexpected pid")
		}
	}
	detector.cmdlineResolver = func(pid uint32) (string, error) {
		switch pid {
		case 100:
			return "bash", nil
		case 200:
			return "bash", nil
		default:
			return "", errors.New("unexpected pid")
		}
	}

	procCh := make(chan collector.ProcessEvent, 1024)
	router := NewRouter(detector, procCh, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := startDetectorPipeline(router, detector, ctx)

	procCh <- collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("bash"),
		Args:      fixedSlotArgs("npm", "install", "lodash"),
		EventType: processEventExec,
	}
	procCh <- collector.ProcessEvent{
		Pid:       200,
		Comm:      fixedComm("bash"),
		Args:      fixedSlotArgs("npm", "i", "axios"),
		EventType: processEventExec,
	}
	procCh <- collector.ProcessEvent{
		Pid:       200,
		Comm:      fixedComm("npm"),
		EventType: processEventExit,
	}
	procCh <- collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("npm"),
		EventType: processEventExit,
	}

	got := map[string]string{}
	for len(got) < 2 {
		select {
		case session := <-detector.Completed():
			got[session.PackageName] = session.Cwd
		case <-time.After(250 * time.Millisecond):
			t.Fatal("timed out waiting for completed sessions")
		}
	}

	if got["lodash"] != "/tmp/project-lodash" {
		t.Fatalf("lodash session cwd = %q, want %q", got["lodash"], "/tmp/project-lodash")
	}
	if got["axios"] != "/tmp/project-axios" {
		t.Fatalf("axios session cwd = %q, want %q", got["axios"], "/tmp/project-axios")
	}

	cancel()
	waitForDetectorExit(t, done)
}

// TestDetector_ShutdownClosesCompleted asserts Detector.Shutdown's entire
// contract: it closes Completed() once ctx is canceled. This is the one piece
// of behavior the removed Detector.Run() actually needed in production (see
// Shutdown's doc comment and AUDIT.md H3) -- no Router or event delivery is
// involved, since Shutdown itself never touches events.
func TestDetector_ShutdownClosesCompleted(t *testing.T) {
	detector := NewDetector(0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		detector.Shutdown(ctx)
	}()

	cancel()
	waitForDetectorExit(t, done)

	select {
	case _, ok := <-detector.Completed():
		if ok {
			t.Fatal("Completed() channel is still open after detector shutdown")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for Completed() to close")
	}
}

func TestDetector_SeedsTrackedRootPIDAndCompletesOnRootExit(t *testing.T) {
	type trackedRoot struct {
		pid  uint32
		ppid uint32
	}

	detector := NewDetector(0)
	detector.cwdResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "/tmp/project-lodash", nil
		}
		return "", errors.New("unexpected pid")
	}
	detector.cmdlineResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "bash", nil
		}
		return "", errors.New("unexpected pid")
	}

	trackedRoots := make(chan trackedRoot, 1)
	detector.SetRootTracker(func(pid, ppid uint32) error {
		trackedRoots <- trackedRoot{pid: pid, ppid: ppid}
		return nil
	})

	procCh := make(chan collector.ProcessEvent, 1024)
	router := NewRouter(detector, procCh, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := startDetectorPipeline(router, detector, ctx)

	procCh <- collector.ProcessEvent{
		Pid:       100,
		Ppid:      42,
		Comm:      fixedComm("bash"),
		Args:      fixedSlotArgs("npm", "install", "lodash"),
		EventType: processEventExec,
	}
	procCh <- collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("npm"),
		EventType: processEventExit,
	}

	select {
	case tracked := <-trackedRoots:
		if tracked.pid != 100 || tracked.ppid != 42 {
			t.Fatalf("tracked root = %+v, want pid=100 ppid=42", tracked)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for root tracker callback")
	}

	select {
	case session := <-detector.Completed():
		if session.PackageName != "lodash" {
			t.Fatalf("session.PackageName = %q, want %q", session.PackageName, "lodash")
		}
		if session.State != SessionComplete {
			t.Fatalf("session.State = %q, want %q", session.State, SessionComplete)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for completed root session")
	}

	cancel()
	waitForDetectorExit(t, done)
}

func TestDetector_ForkOnlyChildrenDoNotBlockCompletion(t *testing.T) {
	detector := NewDetector(0)
	detector.cwdResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "/tmp/project-lodash", nil
		}
		return "", errors.New("unexpected pid")
	}
	detector.cmdlineResolver = func(pid uint32) (string, error) {
		if pid == 100 {
			return "bash", nil
		}
		return "", errors.New("unexpected pid")
	}

	procCh := make(chan collector.ProcessEvent, 1024)
	router := NewRouter(detector, procCh, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := startDetectorPipeline(router, detector, ctx)

	procCh <- collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("bash"),
		Args:      fixedSlotArgs("npm", "install", "lodash"),
		EventType: processEventExec,
	}
	procCh <- collector.ProcessEvent{
		Pid:       101,
		Ppid:      100,
		Comm:      fixedComm("node"),
		EventType: processEventFork,
	}
	procCh <- collector.ProcessEvent{
		Pid:       102,
		Ppid:      100,
		Comm:      fixedComm("node"),
		EventType: processEventFork,
	}
	procCh <- collector.ProcessEvent{
		Pid:       100,
		Comm:      fixedComm("npm"),
		EventType: processEventExit,
	}

	select {
	case session := <-detector.Completed():
		if session.PackageName != "lodash" {
			t.Fatalf("session.PackageName = %q, want %q", session.PackageName, "lodash")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for completed session after root exit")
	}

	cancel()
	waitForDetectorExit(t, done)
}

func TestParseInstallTarget(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{command: "install lodash", want: "lodash"},
		{command: "npm i axios", want: "axios"},
		{command: "install --save-dev typescript", want: "typescript"},
		{command: "npm install", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := parseInstallTarget(tt.command)
			if got != tt.want {
				t.Fatalf("parseInstallTarget(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestDecodeArgsFixedSlots(t *testing.T) {
	args := fixedSlotArgs("npm", "install", "lodash", "--save-dev", "typescript")

	got := decodeArgs(args)
	want := "npm install lodash --save-dev typescript"
	if got != want {
		t.Fatalf("decodeArgs(fixed slots) = %q, want %q", got, want)
	}
}

func TestIsNpmInstallInvocation_FixedSlotArgs(t *testing.T) {
	event := collector.ProcessEvent{
		Comm: fixedComm("bash"),
		Args: fixedSlotArgs("npm", "install", "lodash"),
	}

	command := decodeArgs(event.Args)
	if !isNpmInstallInvocation(event, command) {
		t.Fatalf("isNpmInstallInvocation(%q) = false, want true", command)
	}
}

func TestIsNpmInstallInvocation_MissingBinaryName(t *testing.T) {
	event := collector.ProcessEvent{
		Comm: fixedComm("bash"),
		Args: fixedSlotArgs("install", "lodash"),
	}

	command := decodeArgs(event.Args)
	if isNpmInstallInvocation(event, command) {
		t.Fatalf("isNpmInstallInvocation(%q) = true, want false", command)
	}
}

func TestResolveCommand_PrefersEventArgsOverStaleCmdline(t *testing.T) {
	detector := NewDetector(0)
	detector.cmdlineResolver = func(pid uint32) (string, error) {
		return "bash", nil
	}

	event := collector.ProcessEvent{
		Pid:  100,
		Comm: fixedComm("bash"),
		Args: fixedSlotArgs("npm", "install", "lodash"),
	}

	got := detector.resolveCommand(event)
	want := "npm install lodash"
	if got != want {
		t.Fatalf("resolveCommand() = %q, want %q", got, want)
	}
}

func fixedArgs(args string) [256]byte {
	var out [256]byte
	copy(out[:], args)
	return out
}

func fixedSlotArgs(parts ...string) [256]byte {
	var out [256]byte

	for i, part := range parts {
		offset := i * 51
		if offset >= len(out) {
			break
		}
		copy(out[offset:offset+51], part)
	}

	return out
}

func waitForDetectorExit(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("detector pipeline (router + shutdown) did not exit in time")
	}
}

func TestSessionTimeout(t *testing.T) {
	const timeout = 100 * time.Millisecond

	detector := NewDetector(timeout)

	procCh := make(chan collector.ProcessEvent, 1024)
	router := NewRouter(detector, procCh, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := startDetectorPipeline(router, detector, ctx)

	// Submit an EXEC for npm install but never send the EXIT.
	procCh <- collector.ProcessEvent{
		Pid:       500,
		Ppid:      1,
		Comm:      fixedComm("npm"),
		Args:      fixedSlotArgs("npm", "install", "lodash"),
		EventType: processEventExec,
	}

	// Wait up to 300ms — the timer should fire after ~100ms.
	var sess *Session
	select {
	case sess = <-detector.Completed():
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timed out waiting for session to be completed by the session timer")
	}

	if sess == nil {
		t.Fatal("Completed() returned nil session")
	}
	if !sess.TimedOut {
		t.Fatalf("session.TimedOut = false, want true")
	}
	if sess.State != SessionComplete {
		t.Fatalf("session.State = %q after timeout, want %q", sess.State, SessionComplete)
	}

	cancel()
	waitForDetectorExit(t, done)
}

// TestDetectorNeverDeliversASessionMoreThanOnceWhenExitRacesTimeout is the
// direct end-to-end reproduction of AUDIT.md C3: "a session can be completed
// twice -- timeout vs. normal-exit race."
//
// It arms an extremely short per-session timeout and submits the matching EXIT
// event for the same PID immediately afterward, so the router goroutine
// (handleExit) and the timer's own goroutine (the time.AfterFunc callback) are
// racing to complete the very same session. Repeated across many independent
// sessions on one live Detector to make the race reliably observable rather
// than dependent on a single lucky (or unlucky) interleaving.
//
// Deliveries are keyed by NpmPID rather than Session.ID: NewSession derives ID
// from time.Now().Unix(), which has one-second resolution, so many sessions
// created in the same tight loop collide on ID even though they are genuinely
// different sessions. NpmPID is unique per trial by construction.
func TestDetectorNeverDeliversASessionMoreThanOnceWhenExitRacesTimeout(t *testing.T) {
	const trials = 300
	const timeout = 1 * time.Microsecond

	detector := NewDetector(timeout)

	procCh := make(chan collector.ProcessEvent, 1024)
	router := NewRouter(detector, procCh, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := startDetectorPipeline(router, detector, ctx)

	for trial := 0; trial < trials; trial++ {
		pid := uint32(20000 + trial)

		procCh <- collector.ProcessEvent{
			Pid:       pid,
			Ppid:      1,
			Comm:      fixedComm("npm"),
			Args:      fixedSlotArgs("npm", "install", "lodash"),
			EventType: processEventExec,
		}
		// Racing the exit right on the timer's heels: the timer is already
		// armed (with a 1us timeout) and may fire before, during, or after
		// this event is processed.
		procCh <- collector.ProcessEvent{
			Pid:       pid,
			EventType: processEventExit,
		}
	}

	deliveries := make(map[uint32]int)
	deadline := time.After(3 * time.Second)
drain:
	for len(deliveries) < trials {
		select {
		case sess := <-detector.Completed():
			deliveries[sess.NpmPID]++
		case <-deadline:
			break drain
		}
	}

	// A duplicate send (if the bug is present) can lag slightly behind the
	// first, since it comes from a different goroutine racing to reach the
	// same channel send. Give stragglers a short further window.
	extra := time.After(100 * time.Millisecond)
extraLoop:
	for {
		select {
		case sess := <-detector.Completed():
			deliveries[sess.NpmPID]++
		case <-extra:
			break extraLoop
		}
	}

	cancel()
	waitForDetectorExit(t, done)

	if len(deliveries) < trials {
		t.Fatalf("only %d of %d sessions were ever completed; the race scenario did not run "+
			"as intended", len(deliveries), trials)
	}

	duplicates := 0
	for pid, count := range deliveries {
		if count > 1 {
			duplicates++
			t.Errorf("session for pid %d was delivered on Completed() %d times, want exactly 1",
				pid, count)
		}
	}
	if duplicates > 0 {
		t.Logf("%d of %d sessions were completed more than once", duplicates, trials)
	}
}

// TestSessionTimeoutClearsItsOwnTimerEntry asserts that a session which
// completes via the timeout callback no longer has an entry in d.timers
// afterward.
//
// Before this fix, only the normal-exit path (handleExit -> stopSessionTimer)
// ever removed an entry from d.timers; the timeout callback itself never did,
// so every session that timed out leaked one *time.Timer map entry for the
// life of the process (AUDIT.md C3's "compounding leak"). A long-running
// monitor capturing many timed-out installs would grow this map without
// bound.
//
// This is a guard, not a fresh red: the leak fix was written as part of the
// same change as the double-completion fix (both live in startSessionTimer's
// callback), so by the time this test was written the code already passed it.
// Checked for teeth rather than trusted: temporarily removing just the
// d.stopSessionTimer(npmPID) cleanup line reproduces the leak and fails this
// test (see evidence/slice3-teeth-check.txt), confirming it is not vacuous.
//
// This reaches d.timers directly because it is unexported detector state with
// no public accessor, and this test lives in the same package -- consistent
// with how the rest of this file already configures unexported fields like
// cwdResolver.
func TestSessionTimeoutClearsItsOwnTimerEntry(t *testing.T) {
	const timeout = 20 * time.Millisecond

	detector := NewDetector(timeout)

	procCh := make(chan collector.ProcessEvent, 1024)
	router := NewRouter(detector, procCh, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := startDetectorPipeline(router, detector, ctx)

	const pid = uint32(30000)
	procCh <- collector.ProcessEvent{
		Pid:       pid,
		Ppid:      1,
		Comm:      fixedComm("npm"),
		Args:      fixedSlotArgs("npm", "install", "lodash"),
		EventType: processEventExec,
	}

	select {
	case sess := <-detector.Completed():
		if !sess.TimedOut {
			t.Fatalf("session.TimedOut = false, want true (it should have completed by timeout)")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for the session to complete by timeout")
	}

	// Give the timeout callback's own cleanup a moment to run -- it clears
	// d.timers itself now, but that happens after the send on Completed(),
	// which is what the select above already waited for.
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		detector.mu.RLock()
		_, leaked := detector.timers[pid]
		remaining := len(detector.timers)
		detector.mu.RUnlock()

		if !leaked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("d.timers still holds an entry for pid %d %s after it timed out "+
				"(map has %d total entries); the timeout callback never cleaned up its own entry",
				pid, "500ms later", remaining)
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	waitForDetectorExit(t, done)
}

// TestDetectorTimedOutStaysFalseWhenExitCompletesBeforeTheTimer asserts that an
// ordinary session, which exits well within its timeout window, reports
// TimedOut=false and is delivered on Completed() exactly once, with the armed
// timer never firing at all.
//
// IMPORTANT -- what this test does NOT do: checked for teeth the same way as
// TestBuildRecordOnCompletedSessionWhileCollectorsStillWrite was in the C2
// fix, and it has none against C3. With a 200ms window and an exit submitted
// essentially instantly, stopSessionTimer successfully cancels the timer well
// before it would fire -- true whether or not MarkCompleteOnce's arbitration
// exists at all, since nothing here creates an actual race between the two
// completion paths. Confirmed by running it against the fully reverted,
// pre-fix detector.go: it still passed (see
// evidence/slice4-teeth-check.txt).
//
// "TimedOut reflects the actual winner" -- the seam this was meant to cover --
// IS genuinely tested with teeth, but at the unit level:
// TestMarkCompleteOnceSetsStateAtomicallyWithTimedOut and
// TestMarkCompleteOnceSecondCallDoesNotOverwriteTheFirstWinner in
// session_test.go construct the exact disagreement (a losing call arguing for
// the opposite TimedOut value) and prove the winner's value survives. The
// Detector layer only ever calls MarkCompleteOnce and trusts its result, so
// there is no separate end-to-end-only bug for a further test to catch here --
// this one is kept as an honest regression guard for the ordinary,
// non-racing case, not as C3 coverage.
func TestDetectorTimedOutStaysFalseWhenExitCompletesBeforeTheTimer(t *testing.T) {
	const timeout = 200 * time.Millisecond

	detector := NewDetector(timeout)

	procCh := make(chan collector.ProcessEvent, 1024)
	router := NewRouter(detector, procCh, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := startDetectorPipeline(router, detector, ctx)

	const pid = uint32(40000)

	procCh <- collector.ProcessEvent{
		Pid:       pid,
		Ppid:      1,
		Comm:      fixedComm("npm"),
		Args:      fixedSlotArgs("npm", "install", "lodash"),
		EventType: processEventExec,
	}
	procCh <- collector.ProcessEvent{
		Pid:       pid,
		EventType: processEventExit,
	}

	var sess *Session
	select {
	case sess = <-detector.Completed():
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for the session to complete via normal exit")
	}

	if sess.TimedOut {
		t.Error("session.TimedOut = true for a session that exited well within its timeout window")
	}
	if sess.State != SessionComplete {
		t.Errorf("session.State = %q, want %q", sess.State, SessionComplete)
	}

	// The timer must not fire at all: wait past the timeout window and confirm
	// no second delivery ever arrives.
	select {
	case second := <-detector.Completed():
		t.Errorf("session was delivered a second time (id=%s) after its timeout window elapsed; "+
			"the armed timer fired despite the session already completing normally", second.ID)
	case <-time.After(timeout + 100*time.Millisecond):
		// Correct: the timer was disarmed by the normal-exit path and never fired.
	}

	cancel()
	waitForDetectorExit(t, done)
}

// TestRouteToSessionCountsAndLogsDropsForUnknownPID pins RouteToSession's own
// contract directly (no Router involved): a call for a PID with no
// registered session must be counted, must log when a verbose logger is
// configured, and -- the negative check that gives this test teeth -- a call
// for a PID that *is* registered must do neither. AUDIT.md H4 is the
// audited gap this closes: the drop itself is architecturally unavoidable
// (five independent ring-buffer-reading goroutines give no cross-channel
// ordering guarantee), but it was previously invisible on both counts.
func TestRouteToSessionCountsAndLogsDropsForUnknownPID(t *testing.T) {
	detector := NewDetector(0)

	var loggedLines []string
	detector.SetLogger(func(format string, args ...any) {
		loggedLines = append(loggedLines, fmt.Sprintf(format, args...))
	})

	if got := detector.DroppedRoutesForUnknownPID(); got != 0 {
		t.Fatalf("DroppedRoutesForUnknownPID() = %d before any calls, want 0", got)
	}

	// Three calls for an unrecognized pid: all three must be counted.
	const unknownPID = uint32(12345)
	for i := 0; i < 3; i++ {
		detector.RouteToSession(unknownPID, func(s *Session) {
			t.Fatal("fn was called for an unregistered pid; RouteToSession should not have found a session")
		})
	}

	if got := detector.DroppedRoutesForUnknownPID(); got != 3 {
		t.Fatalf("DroppedRoutesForUnknownPID() = %d after 3 unknown-pid calls, want 3", got)
	}
	if len(loggedLines) != 3 {
		t.Fatalf("verbose logger received %d line(s), want 3", len(loggedLines))
	}
	for _, line := range loggedLines {
		if !strings.Contains(line, fmt.Sprintf("pid=%d", unknownPID)) {
			t.Errorf("logged line %q does not mention pid=%d", line, unknownPID)
		}
	}

	// The negative check: a registered pid must not be counted or logged.
	session := NewSession(unknownPID+1, "pkg")
	detector.registerSession(session)
	detector.associatePID(session, unknownPID+1)

	called := false
	detector.RouteToSession(unknownPID+1, func(s *Session) { called = true })

	if !called {
		t.Fatal("fn was not called for a registered pid")
	}
	if got := detector.DroppedRoutesForUnknownPID(); got != 3 {
		t.Fatalf("DroppedRoutesForUnknownPID() = %d after a known-pid call, want unchanged at 3", got)
	}
	if len(loggedLines) != 3 {
		t.Fatalf("verbose logger received %d line(s) after a known-pid call, want unchanged at 3", len(loggedLines))
	}
}
