package session

import (
	"bytes"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
)

// SessionState describes the lifecycle phase of one npm install session.
type SessionState string

const (
	SessionWaiting  SessionState = "waiting"
	SessionActive   SessionState = "active"
	SessionComplete SessionState = "complete"
)

// Session tracks one npm install invocation and the features collected for it.
type Session struct {
	mu           sync.Mutex
	completeOnce sync.Once

	ID          string
	PackageName string
	Cwd         string
	NpmPID      uint32
	ChildPIDs   map[uint32]bool
	LivePIDs    map[uint32]bool
	State       SessionState
	StartTime   time.Time
	EndTime     time.Time

	FiletopAgg *features.FiletopAggregator
	DirCounts  *features.DirCounts
	TCPAgg     *features.TCPAggregator
	NGramCtr   *features.NGramCounter
	Evidence   *features.EvidenceCollector

	SyscallCounts map[features.SyscallCategory]int
	ProcessTree   string
	TimedOut      bool
}

// NewSession creates an initialized npm install session.
func NewSession(npmPID uint32, packageName string) *Session {
	startTime := time.Now()
	if packageName == "" {
		packageName = "unknown"
	}

	return &Session{
		ID:            fmt.Sprintf("npm-%d", startTime.Unix()),
		PackageName:   packageName,
		NpmPID:        npmPID,
		ChildPIDs:     make(map[uint32]bool),
		LivePIDs:      map[uint32]bool{npmPID: true},
		State:         SessionActive,
		StartTime:     startTime,
		FiletopAgg:    features.NewFiletopAggregator(),
		DirCounts:     &features.DirCounts{},
		TCPAgg:        features.NewTCPAggregator(),
		NGramCtr:      features.NewNGramCounter(),
		Evidence:      features.NewEvidenceCollector(),
		SyscallCounts: make(map[features.SyscallCategory]int),
		ProcessTree:   fmt.Sprintf("npm(%d)", npmPID),
	}
}

// AddProcess records a child process as part of the session process tree.
func (s *Session) AddProcess(event collector.ProcessEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ChildPIDs == nil {
		s.ChildPIDs = make(map[uint32]bool)
	}
	if s.Evidence == nil {
		s.Evidence = features.NewEvidenceCollector()
	}

	comm := decodeComm(event.Comm)
	s.ChildPIDs[event.Pid] = true
	s.ProcessTree += fmt.Sprintf("->%s(%d)", comm, event.Pid)
	s.Evidence.AddProcess(comm, decodeArgs(event.Args), event.TimestampNs)
}

// AddSyscall records one syscall against the session category and n-gram data.
func (s *Session) AddSyscall(event collector.SyscallEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.SyscallCounts == nil {
		s.SyscallCounts = make(map[features.SyscallCategory]int)
	}
	if s.NGramCtr == nil {
		s.NGramCtr = features.NewNGramCounter()
	}

	category := features.Categorise(event.SyscallID)
	s.SyscallCounts[category]++
	s.NGramCtr.Push(event.SyscallID)
}

// AddFile forwards one file event into the session's file activity summary.
func (s *Session) AddFile(event collector.FileEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.FiletopAgg == nil {
		s.FiletopAgg = features.NewFiletopAggregator()
	}
	if s.DirCounts == nil {
		s.DirCounts = &features.DirCounts{}
	}
	if s.Evidence == nil {
		s.Evidence = features.NewEvidenceCollector()
	}

	s.FiletopAgg.Add(event)
	s.DirCounts.Add(event.DirCategory)
	s.Evidence.AddPath(decodeFilename(event.Filename), event.Flags, event.TimestampNs)
}

// AddTCP forwards one TCP state transition into the session TCP summary.
func (s *Session) AddTCP(event collector.TCPEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.TCPAgg == nil {
		s.TCPAgg = features.NewTCPAggregator()
	}
	if s.Evidence == nil {
		s.Evidence = features.NewEvidenceCollector()
	}

	s.TCPAgg.Add(features.TCPEvent{
		Pid:         event.Pid,
		Saddr:       event.Saddr,
		Daddr:       event.Daddr,
		Sport:       event.Sport,
		Dport:       event.Dport,
		OldState:    event.OldState,
		NewState:    event.NewState,
		TimestampNs: event.TimestampNs,
	})

	// isRoot: whether this connection came from the session's own npm root
	// PID rather than a spawned child. There is no DNS name in these events
	// -- only a raw IPv4 address -- so "is this the registry?" is
	// unanswerable, but "did the postinstall script itself open a socket?"
	// is both answerable and the stronger discriminator (verdict's NET-001).
	isRoot := event.Pid == s.NpmPID
	s.Evidence.AddEndpoint(features.FormatEndpoint(event.Daddr, event.Dport), isRoot, event.TimestampNs)
}

// AddBytes records real TCP byte counts into the session's file-transfer
// summary.  Direction 0 means bytes received (tcp_recvmsg retval);
// direction 1 means bytes sent (tcp_sendmsg size argument).
func (s *Session) AddBytes(event collector.BytesEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.FiletopAgg == nil {
		s.FiletopAgg = features.NewFiletopAggregator()
	}

	if event.Direction == 0 {
		s.FiletopAgg.AddReadBytes(event.Pid, int(event.Bytes))
	} else {
		s.FiletopAgg.AddWriteBytes(event.Pid, int(event.Bytes))
	}
}

// Complete marks the session as finished and records its end time.
func (s *Session) Complete() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.State = SessionComplete
	s.EndTime = time.Now()
}

// TrackPID records one process as part of the session's live process set.
func (s *Session) TrackPID(pid uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.LivePIDs == nil {
		s.LivePIDs = make(map[uint32]bool)
	}

	s.LivePIDs[pid] = true
}

// HasLivePID reports whether pid is currently counted in the session's live
// process set.
func (s *Session) HasLivePID(pid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.LivePIDs[pid]
}

// ExitPID removes one process from the session's live process set and returns
// the number of tracked processes still running.
func (s *Session) ExitPID(pid uint32) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.LivePIDs == nil {
		return 0
	}

	delete(s.LivePIDs, pid)
	return len(s.LivePIDs)
}

// HasChildPID reports whether the session has already recorded pid in its
// process tree.
func (s *Session) HasChildPID(pid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ChildPIDs[pid]
}

func decodeComm(comm [16]byte) string {
	end := bytes.IndexByte(comm[:], 0)
	if end == -1 {
		end = len(comm)
	}

	return string(comm[:end])
}

// decodeFilename trims a NUL-terminated C string out of FileEvent's fixed
// size byte array. The field is only populated at all since the
// pending_open fix carried the path through from the enter probe (AUDIT.md
// H-series follow-up); before that it was always zero and this would always
// decode to "".
func decodeFilename(filename [256]byte) string {
	end := bytes.IndexByte(filename[:], 0)
	if end == -1 {
		end = len(filename)
	}

	return string(filename[:end])
}

// Snapshot is a point-in-time copy of everything a consumer needs to build an
// output record from a Session.
//
// It exists so readers never touch Session's fields directly. Session's mutex
// is unexported and every mutator takes it; a reader that reaches in without it
// races those writers, and because SyscallCounts and the TCP aggregator's sets
// are Go maps, that race is not merely inconsistent data -- it is
// "fatal error: concurrent map read and map write", an unrecoverable crash that
// loses every in-flight session (AUDIT.md C2).
type Snapshot struct {
	ID          string
	PackageName string
	Cwd         string
	ProcessTree string
	State       SessionState
	TimedOut    bool
	StartTime   time.Time
	EndTime     time.Time

	SyscallCounts map[features.SyscallCategory]int
	Filetop       features.FiletopCounts
	Opensnoop     map[string]int
	TCP           features.TCPCounts
	Patterns      features.PatternCounts
	Evidence      features.Evidence
}

// Snapshot returns a consistent point-in-time copy of the session's collected
// features.
//
// Every field is read under a single acquisition of s.mu, so the returned value
// reflects one coherent instant rather than fields sampled at different times.
// Maps are cloned rather than shared, so later writes to the session cannot
// mutate a snapshot a caller is still reading.
func (s *Session) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap := Snapshot{
		ID:          s.ID,
		PackageName: s.PackageName,
		Cwd:         s.Cwd,
		ProcessTree: s.ProcessTree,
		State:       s.State,
		TimedOut:    s.TimedOut,
		StartTime:   s.StartTime,
		EndTime:     s.EndTime,

		SyscallCounts: maps.Clone(s.SyscallCounts),
		Opensnoop:     (&features.DirCounts{}).ToMap(),
	}

	if snap.SyscallCounts == nil {
		snap.SyscallCounts = make(map[features.SyscallCategory]int)
	}

	// These aggregators have no mutex of their own (except FiletopAggregator)
	// and rely entirely on s.mu, which is held here.
	if s.FiletopAgg != nil {
		snap.Filetop = s.FiletopAgg.Snapshot()
	}
	if s.DirCounts != nil {
		snap.Opensnoop = s.DirCounts.ToMap()
	}
	if s.TCPAgg != nil {
		snap.TCP = s.TCPAgg.Counts()
	}
	if s.NGramCtr != nil {
		snap.Patterns = s.NGramCtr.Snapshot()
	}
	if s.Evidence != nil {
		snap.Evidence = s.Evidence.Snapshot()
	}

	return snap
}

// MarkCompleteOnce marks the session complete exactly once, no matter how many
// goroutines call it concurrently, and reports whether this call was the one
// that did it.
//
// A session can be completed from two independent goroutines racing each
// other: the normal-exit path (the router goroutine, when the last live PID
// exits) and the timeout callback (a *time.Timer's own goroutine, firing
// time.AfterFunc). Without a single arbitration point, both could decide they
// are the one completing the session and both hand it to the output pipeline,
// producing a duplicate session record (AUDIT.md C3).
//
// The winner's timedOut value is the one that sticks -- a losing call is a
// complete no-op, including for TimedOut, so a session that genuinely
// completed via normal exit can never be silently flipped to "timed out" by a
// timeout callback that fires moments later on the same session.
//
// TimedOut, State and EndTime are set together under one lock acquisition by
// the winner, so a concurrent Snapshot() never observes them out of step with
// each other -- and, unlike the code this replaces, TimedOut is never written
// outside the lock.
func (s *Session) MarkCompleteOnce(timedOut bool) bool {
	won := false
	s.completeOnce.Do(func() {
		won = true
		s.mu.Lock()
		s.TimedOut = timedOut
		s.State = SessionComplete
		s.EndTime = time.Now()
		s.mu.Unlock()
	})
	return won
}
