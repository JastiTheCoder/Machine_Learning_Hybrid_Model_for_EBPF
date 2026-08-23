package session

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
)

const (
	processEventExec uint8 = iota
	processEventFork
	processEventExit
)

// Detector manages npm-install session lifecycles and routes collector events
// into the active session associated with each tracked PID.
type Detector struct {
	activeSessions    map[uint32]*Session
	pidToSession      map[uint32]*Session
	completedSessions chan *Session
	timers            map[uint32]*time.Timer
	sessionTimeout    time.Duration

	cwdResolver     func(uint32) (string, error)
	cmdlineResolver func(uint32) (string, error)
	rootTracker     func(uint32, uint32) error
	logger          func(string, ...any)

	mu              sync.RWMutex
	completedMu     sync.RWMutex
	completedClosed bool
}

// NewDetector creates a ready-to-run detector for routed collector events.
// sessionTimeout is the maximum duration a session may remain active before
// being forcibly completed. Pass 0 to disable the timeout.
func NewDetector(sessionTimeout time.Duration) *Detector {
	return &Detector{
		activeSessions:    make(map[uint32]*Session),
		pidToSession:      make(map[uint32]*Session),
		completedSessions: make(chan *Session, 100),
		timers:            make(map[uint32]*time.Timer),
		sessionTimeout:    sessionTimeout,
		cwdResolver:       readProcessCwd,
		cmdlineResolver:   readProcessCmdline,
	}
}

// SetRootTracker configures an optional hook that seeds the shared kernel
// tracked_pids map once userspace recognizes a new npm root process.
func (d *Detector) SetRootTracker(track func(uint32, uint32) error) {
	d.rootTracker = track
}

// SetLogger configures an optional verbose logger for detector diagnostics.
func (d *Detector) SetLogger(logger func(string, ...any)) {
	d.logger = logger
}

// Shutdown blocks until ctx is canceled, then closes the Completed() channel.
//
// Event delivery itself happens through HandleProcess and RouteToSession,
// called directly by Router.Run -- this method's only job is the one
// production actually needs from a long-lived detector goroutine: knowing
// when to close Completed() so a consumer ranging over it (cmd/monitor's
// output worker) terminates cleanly on shutdown, rather than blocking
// forever. Run it in its own goroutine alongside Router.Run:
//
//	go detector.Shutdown(ctx)
//	go router.Run(ctx)
//
// This replaces the former Run()/SubmitProcess/SubmitSyscall/SubmitFile/
// SubmitTCP machinery (AUDIT.md H3): those methods queued events onto
// Detector's own private channels and a Run() loop drained them, but
// production never called Submit* -- Router.Run has always called
// HandleProcess/RouteToSession directly. That queueing layer had no
// caller outside detector_test.go, so most of this package's own test
// coverage exercised a path the real binary never executed. See
// docs/bugs-fixed/fix-dead-detector-run/ for the removal and the test
// migration onto the real Router-driven path.
func (d *Detector) Shutdown(ctx context.Context) {
	<-ctx.Done()
	d.closeCompletedSessions()
}

// HandleProcess applies one process lifecycle event to detector state.
func (d *Detector) HandleProcess(event collector.ProcessEvent) {
	d.completedMu.RLock()
	defer d.completedMu.RUnlock()

	if d.completedClosed {
		return
	}

	d.handleProcess(event)
}

// RouteToSession finds the session for pid and applies fn when present.
func (d *Detector) RouteToSession(pid uint32, fn func(*Session)) {
	if fn == nil {
		return
	}

	d.completedMu.RLock()
	defer d.completedMu.RUnlock()

	if d.completedClosed {
		return
	}

	d.mu.RLock()
	session := d.pidToSession[pid]
	d.mu.RUnlock()
	if session == nil {
		return
	}

	d.ensureLivePID(session, pid)
	fn(session)
}

// Completed returns the stream of completed npm sessions.
func (d *Detector) Completed() <-chan *Session {
	return d.completedSessions
}

func (d *Detector) handleProcess(event collector.ProcessEvent) {
	d.logf(
		"process event: pid=%d ppid=%d type=%s comm=%q args=%q is_npm_related=%t",
		event.Pid,
		event.Ppid,
		processEventTypeString(event.EventType),
		decodeComm(event.Comm),
		strings.TrimSpace(decodeArgs(event.Args)),
		event.IsNpmRelated != 0,
	)

	switch event.EventType {
	case processEventExec:
		d.handleExec(event)
	case processEventFork:
		d.handleFork(event)
	case processEventExit:
		d.handleExit(event)
	}
}

func (d *Detector) handleExec(event collector.ProcessEvent) {
	if session := d.sessionForPID(event.Pid); session != nil {
		d.ensureLivePID(session, event.Pid)
		d.attachExec(session, event)
		return
	}

	if session := d.sessionForPID(event.Ppid); session != nil {
		d.ensureLivePID(session, event.Pid)
		d.attachExec(session, event)
		return
	}

	command := d.resolveCommand(event)
	if !isNpmInstallInvocation(event, command) {
		d.logf(
			"ignored exec pid=%d ppid=%d comm=%q command=%q: not an npm install invocation",
			event.Pid,
			event.Ppid,
			decodeComm(event.Comm),
			command,
		)
		return
	}

	packageName := parseInstallTarget(command)
	d.logf(
		"parsed npm install target for pid=%d: package=%q command=%q",
		event.Pid,
		packageName,
		command,
	)

	session := NewSession(event.Pid, packageName)

	if cwd, err := d.cwdResolver(event.Pid); err == nil {
		session.Cwd = cwd
	}

	d.registerSession(session)
	d.logf(
		"created session id=%s pid=%d ppid=%d package=%q cwd=%q",
		session.ID,
		session.NpmPID,
		event.Ppid,
		session.PackageName,
		session.Cwd,
	)

	if d.rootTracker != nil {
		if err := d.rootTracker(event.Pid, event.Ppid); err != nil {
			d.logf(
				"failed to seed tracked pid pid=%d ppid=%d session=%s: %v",
				event.Pid,
				event.Ppid,
				session.ID,
				err,
			)
		} else {
			d.logf(
				"seeded tracked pid pid=%d ppid=%d session=%s",
				event.Pid,
				event.Ppid,
				session.ID,
			)
		}
	}

	d.startSessionTimer(session)
}

func (d *Detector) handleFork(event collector.ProcessEvent) {
	session := d.sessionForPID(event.Ppid)
	if session == nil {
		return
	}

	d.associatePID(session, event.Pid)
	d.logf(
		"attached fork pid=%d ppid=%d session=%s",
		event.Pid,
		event.Ppid,
		session.ID,
	)
}

func (d *Detector) handleExit(event collector.ProcessEvent) {
	session := d.sessionForPID(event.Pid)
	if session == nil {
		return
	}

	remaining := session.ExitPID(event.Pid)
	d.untrackPID(event.Pid)
	d.logf(
		"attached exit pid=%d remaining=%d session=%s",
		event.Pid,
		remaining,
		session.ID,
	)
	if remaining > 0 {
		return
	}

	// Always stop/clear our timer entry here, whether or not we go on to win
	// the completion race below -- otherwise a session that also times out
	// around now leaks its *time.Timer entry in d.timers forever (AUDIT.md
	// C3's "compounding leak").
	d.stopSessionTimer(session.NpmPID)

	if !session.MarkCompleteOnce(false) {
		// The timeout callback, racing on its own goroutine, already
		// completed this session first. Do not unregister or send it again --
		// that already happened once and this delivery would be a duplicate.
		d.logf(
			"session id=%s pid=%d already completed by timeout; skipping duplicate completion",
			session.ID,
			session.NpmPID,
		)
		return
	}

	d.unregisterSession(session)
	d.logf(
		"completed session id=%s pid=%d package=%q",
		session.ID,
		session.NpmPID,
		session.PackageName,
	)
	d.completedSessions <- session
}

func (d *Detector) handleSyscall(event collector.SyscallEvent) {
	d.RouteToSession(event.Pid, func(session *Session) {
		session.AddSyscall(event)
	})
}

func (d *Detector) handleFile(event collector.FileEvent) {
	d.RouteToSession(event.Pid, func(session *Session) {
		session.AddFile(event)
	})
}

func (d *Detector) handleTCP(event collector.TCPEvent) {
	d.RouteToSession(event.Pid, func(session *Session) {
		session.AddTCP(event)
	})
}

func (d *Detector) attachExec(session *Session, event collector.ProcessEvent) {
	if event.Pid == session.NpmPID || session.HasChildPID(event.Pid) {
		return
	}

	session.AddProcess(event)
}

func (d *Detector) registerSession(session *Session) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.activeSessions[session.NpmPID] = session
	d.pidToSession[session.NpmPID] = session
}

func (d *Detector) unregisterSession(session *Session) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.activeSessions, session.NpmPID)

	for pid, mapped := range d.pidToSession {
		if mapped == session {
			delete(d.pidToSession, pid)
		}
	}
}

func (d *Detector) trackPID(session *Session, pid uint32) {
	session.TrackPID(pid)

	d.mu.Lock()
	d.pidToSession[pid] = session
	d.mu.Unlock()
}

func (d *Detector) associatePID(session *Session, pid uint32) {
	d.mu.Lock()
	d.pidToSession[pid] = session
	d.mu.Unlock()
}

func (d *Detector) ensureLivePID(session *Session, pid uint32) {
	if pid == 0 || session.HasLivePID(pid) {
		return
	}

	d.trackPID(session, pid)
}

func (d *Detector) untrackPID(pid uint32) {
	d.mu.Lock()
	delete(d.pidToSession, pid)
	d.mu.Unlock()
}

func (d *Detector) sessionForPID(pid uint32) *Session {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.pidToSession[pid]
}

func (d *Detector) closeCompletedSessions() {
	d.completedMu.Lock()
	defer d.completedMu.Unlock()

	if d.completedClosed {
		return
	}

	close(d.completedSessions)
	d.completedClosed = true
}

// startSessionTimer arms a timeout for the given session if d.sessionTimeout > 0.
func (d *Detector) startSessionTimer(s *Session) {
	if d.sessionTimeout <= 0 {
		return
	}

	npmPID := s.NpmPID
	timer := time.AfterFunc(d.sessionTimeout, func() {
		// Always clear our own entry from d.timers first, whether or not we
		// go on to win the completion race below -- this is the callback's
		// only chance to do so; nothing else ever cleans up a timer entry on
		// its behalf (AUDIT.md C3's "compounding leak"). stopSessionTimer
		// also calls Stop() on a timer that has already fired, which is a
		// documented no-op, so this is safe to call unconditionally.
		d.stopSessionTimer(npmPID)

		if !s.MarkCompleteOnce(true) {
			// The normal-exit path, racing on the router goroutine, already
			// completed this session first. Do not send it again.
			return
		}

		slog.Warn("session timed out", "session_id", s.ID, "package", s.PackageName)

		d.completedMu.RLock()
		defer d.completedMu.RUnlock()
		if d.completedClosed {
			return
		}

		d.unregisterSession(s)
		d.completedSessions <- s
	})

	d.mu.Lock()
	d.timers[npmPID] = timer
	d.mu.Unlock()
}

// stopSessionTimer stops and removes the timer for npmPID (if any).
func (d *Detector) stopSessionTimer(npmPID uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if t, ok := d.timers[npmPID]; ok {
		t.Stop()
		delete(d.timers, npmPID)
	}
}

func (d *Detector) logf(format string, args ...any) {
	if d.logger != nil {
		d.logger(format, args...)
	}
}

func (d *Detector) resolveCommand(event collector.ProcessEvent) string {
	command := strings.TrimSpace(decodeArgs(event.Args))
	if command != "" {
		return command
	}

	if d.cmdlineResolver != nil {
		if command, err := d.cmdlineResolver(event.Pid); err == nil {
			command = strings.TrimSpace(command)
			if command != "" {
				return command
			}
		}
	}

	return ""
}

func isNpmInstallInvocation(event collector.ProcessEvent, command string) bool {
	fields := strings.Fields(command)
	if installTokenIndex(fields) == -1 {
		return false
	}

	comm := decodeComm(event.Comm)
	if comm == "npm" {
		return true
	}

	for _, field := range fields {
		base := filepath.Base(field)
		if strings.Contains(base, "npm") {
			return true
		}
	}

	return false
}

func parseInstallTarget(command string) string {
	fields := strings.Fields(command)
	installIndex := installTokenIndex(fields)
	if installIndex == -1 {
		return ""
	}

	for _, field := range fields[installIndex+1:] {
		if strings.HasPrefix(field, "-") {
			continue
		}

		return field
	}

	return ""
}

func installTokenIndex(fields []string) int {
	for i, field := range fields {
		switch field {
		case "install", "i":
			return i
		}
	}

	return -1
}

func readProcessCwd(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
}

func readProcessCmdline(pid uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "", err
	}

	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		return "", nil
	}

	parts := bytes.Split(data, []byte{0})
	fields := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		fields = append(fields, string(part))
	}

	return strings.Join(fields, " "), nil
}

func decodeArgs(args [256]byte) string {
	raw := bytes.TrimRight(args[:], "\x00")
	if len(raw) == 0 {
		return ""
	}

	parts := bytes.Split(raw, []byte{0})
	fields := make([]string, 0, len(parts))
	for _, part := range parts {
		part = bytes.TrimSpace(part)
		if len(part) == 0 {
			continue
		}
		fields = append(fields, string(part))
	}

	return strings.Join(fields, " ")
}

func processEventTypeString(eventType uint8) string {
	switch eventType {
	case processEventExec:
		return "exec"
	case processEventFork:
		return "fork"
	case processEventExit:
		return "exit"
	default:
		return fmt.Sprintf("unknown(%d)", eventType)
	}
}
