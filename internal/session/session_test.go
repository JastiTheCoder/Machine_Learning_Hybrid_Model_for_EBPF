package session

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
)

func TestNewSession(t *testing.T) {
	before := time.Now()
	session := NewSession(4242, "left-pad")
	after := time.Now()

	if session == nil {
		t.Fatal("NewSession() returned nil")
	}
	if session.PackageName != "left-pad" {
		t.Fatalf("PackageName = %q, want %q", session.PackageName, "left-pad")
	}
	if session.NpmPID != 4242 {
		t.Fatalf("NpmPID = %d, want %d", session.NpmPID, 4242)
	}
	if session.State != SessionActive {
		t.Fatalf("State = %q, want %q", session.State, SessionActive)
	}
	if session.StartTime.IsZero() {
		t.Fatal("StartTime is zero, want non-zero")
	}
	if session.StartTime.Before(before) || session.StartTime.After(after) {
		t.Fatalf("StartTime = %v, want between %v and %v", session.StartTime, before, after)
	}
	if !session.EndTime.IsZero() {
		t.Fatalf("EndTime = %v, want zero", session.EndTime)
	}
	if session.ProcessTree != "npm(4242)" {
		t.Fatalf("ProcessTree = %q, want %q", session.ProcessTree, "npm(4242)")
	}
	if !strings.HasPrefix(session.ID, "npm-") {
		t.Fatalf("ID = %q, want prefix %q", session.ID, "npm-")
	}
	if _, err := strconv.ParseInt(strings.TrimPrefix(session.ID, "npm-"), 10, 64); err != nil {
		t.Fatalf("ID timestamp suffix is not numeric: %v", err)
	}
	if session.ChildPIDs == nil {
		t.Fatal("ChildPIDs is nil, want initialized map")
	}
	if session.LivePIDs == nil {
		t.Fatal("LivePIDs is nil, want initialized map")
	}
	if !session.LivePIDs[4242] {
		t.Fatal("LivePIDs missing root npm pid")
	}
	if session.SyscallCounts == nil {
		t.Fatal("SyscallCounts is nil, want initialized map")
	}
	if session.FiletopAgg == nil {
		t.Fatal("FiletopAgg is nil, want initialized aggregator")
	}
	if session.DirCounts == nil {
		t.Fatal("DirCounts is nil, want initialized counter")
	}
	if session.TCPAgg == nil {
		t.Fatal("TCPAgg is nil, want initialized aggregator")
	}
	if session.NGramCtr == nil {
		t.Fatal("NGramCtr is nil, want initialized counter")
	}
}

func TestAddProcess(t *testing.T) {
	session := NewSession(9001, "pkg")

	tests := []struct {
		name    string
		event   collector.ProcessEvent
		wantPID uint32
		wantStr string
	}{
		{
			name:    "shell",
			event:   collector.ProcessEvent{Pid: 111, Comm: fixedComm("sh")},
			wantPID: 111,
			wantStr: "->sh(111)",
		},
		{
			name:    "node",
			event:   collector.ProcessEvent{Pid: 222, Comm: fixedComm("node")},
			wantPID: 222,
			wantStr: "->node(222)",
		},
	}

	wantTree := "npm(9001)"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session.AddProcess(tt.event)
			wantTree += tt.wantStr

			if !session.ChildPIDs[tt.wantPID] {
				t.Fatalf("ChildPIDs missing pid %d after AddProcess", tt.wantPID)
			}
			if session.ProcessTree != wantTree {
				t.Fatalf("ProcessTree = %q, want %q", session.ProcessTree, wantTree)
			}
		})
	}
}

func TestAddSyscall(t *testing.T) {
	session := NewSession(101, "pkg")

	session.AddSyscall(collector.SyscallEvent{Pid: 101, SyscallID: 257})

	if got := session.SyscallCounts[features.CategoryFile]; got != 1 {
		t.Fatalf("SyscallCounts[CategoryFile] = %d, want 1", got)
	}

	for _, syscallID := range []uint32{262, 257, 5} {
		session.AddSyscall(collector.SyscallEvent{Pid: 101, SyscallID: syscallID})
	}

	if got := session.NGramCtr.Snapshot().P1; got != 1 {
		t.Fatalf("NGramCtr.Snapshot().P1 = %d, want 1", got)
	}
	if got := session.SyscallCounts[features.CategoryFile]; got != 4 {
		t.Fatalf("SyscallCounts[CategoryFile] = %d, want 4", got)
	}
}

func TestStateTransition(t *testing.T) {
	session := NewSession(202, "pkg")

	session.Complete()

	if session.State != SessionComplete {
		t.Fatalf("State = %q, want %q", session.State, SessionComplete)
	}
	if session.EndTime.IsZero() {
		t.Fatal("EndTime is zero, want non-zero")
	}
	if session.EndTime.Before(session.StartTime) {
		t.Fatalf("EndTime = %v, want at or after StartTime %v", session.EndTime, session.StartTime)
	}
}

func TestAddFileUpdatesDirCounts(t *testing.T) {
	session := NewSession(404, "pkg")

	session.AddFile(collector.FileEvent{
		Pid:         404,
		DirCategory: uint8(collector.DirTemp),
		Flags:       uint32(syscall.O_RDONLY),
	})

	if session.DirCounts.Temp != 1 {
		t.Fatalf("DirCounts.Temp = %d, want 1", session.DirCounts.Temp)
	}

	fileCounts := session.FiletopAgg.Snapshot()
	if fileCounts.FileAccessProcesses != 1 {
		t.Fatalf("FileAccessProcesses = %d, want 1", fileCounts.FileAccessProcesses)
	}
}

func TestConcurrency(t *testing.T) {
	session := NewSession(303, "pkg")

	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		i := i
		wg.Add(1)

		go func() {
			defer wg.Done()

			pid := uint32(1000 + i)
			syscallIDs := []uint32{257, 262, 5, 41}
			flags := uint32(syscall.O_RDONLY)
			if i%2 == 1 {
				flags = uint32(syscall.O_WRONLY)
			}

			session.AddProcess(collector.ProcessEvent{
				Pid:  pid,
				Comm: fixedComm("node"),
			})
			session.AddSyscall(collector.SyscallEvent{
				Pid:       pid,
				SyscallID: syscallIDs[i%len(syscallIDs)],
			})
			session.AddFile(collector.FileEvent{
				Pid:   pid,
				Flags: flags,
			})
			session.AddTCP(collector.TCPEvent{
				Pid:      pid,
				Saddr:    uint32(i + 1),
				Daddr:    uint32(i + 10_001),
				Sport:    uint16(3000 + i),
				Dport:    uint16(4000 + i),
				OldState: 1,
				NewState: 2,
			})
		}()
	}

	wg.Wait()

	if got := len(session.ChildPIDs); got != 100 {
		t.Fatalf("len(ChildPIDs) = %d, want 100", got)
	}

	totalSyscalls := 0
	for _, count := range session.SyscallCounts {
		totalSyscalls += count
	}
	if totalSyscalls != 100 {
		t.Fatalf("total syscall counts = %d, want 100", totalSyscalls)
	}

	fileCounts := session.FiletopAgg.Snapshot()
	if fileCounts.FileAccessProcesses != 100 {
		t.Fatalf("FileAccessProcesses = %d, want 100", fileCounts.FileAccessProcesses)
	}
	if fileCounts.ReadProcesses == 0 {
		t.Fatal("ReadProcesses = 0, want non-zero")
	}
	if fileCounts.WriteProcesses == 0 {
		t.Fatal("WriteProcesses = 0, want non-zero")
	}
	if got := session.DirCounts.Root + session.DirCounts.Temp + session.DirCounts.Home + session.DirCounts.UserLib + session.DirCounts.Sys + session.DirCounts.Etc + session.DirCounts.Other; got != 100 {
		t.Fatalf("directory event count = %d, want 100", got)
	}

	tcpCounts := session.TCPAgg.Counts()
	if tcpCounts.StateTransitions != 100 {
		t.Fatalf("StateTransitions = %d, want 100", tcpCounts.StateTransitions)
	}
	if tcpCounts.LocalPorts != 100 {
		t.Fatalf("LocalPorts = %d, want 100", tcpCounts.LocalPorts)
	}
	if tcpCounts.RemotePorts != 100 {
		t.Fatalf("RemotePorts = %d, want 100", tcpCounts.RemotePorts)
	}
	if tcpCounts.LocalIPs != 100 {
		t.Fatalf("LocalIPs = %d, want 100", tcpCounts.LocalIPs)
	}
	if tcpCounts.RemoteIPs != 100 {
		t.Fatalf("RemoteIPs = %d, want 100", tcpCounts.RemoteIPs)
	}
}

func fixedComm(comm string) [16]byte {
	var out [16]byte
	copy(out[:], comm)
	return out
}

// TestSnapshotIsIndependentOfLaterMutation asserts that Snapshot returns a
// point-in-time value that later writes to the Session cannot alter.
//
// This is the defining property of a snapshot, and the one that a naive
// implementation gets wrong: SyscallCounts is a map, so returning it directly
// hands the caller a live reference into the Session. The reader would then see
// counts change under it mid-read -- and, because the writers mutate that same
// map from another goroutine, Go would abort the process with
// "fatal error: concurrent map read and map write" (AUDIT.md C2).
//
// Asserting independence rather than equality also keeps the test honest: it
// cannot pass by construction, because it compares the snapshot against values
// captured before a mutation that provably happened.
func TestSnapshotIsIndependentOfLaterMutation(t *testing.T) {
	session := NewSession(303, "pkg")

	session.AddProcess(collector.ProcessEvent{Pid: 1001, Comm: fixedComm("node")})
	for _, id := range []uint32{257, 262, 5, 41} {
		session.AddSyscall(collector.SyscallEvent{Pid: 1001, SyscallID: id})
	}

	snap := session.Snapshot()

	// Values captured at snapshot time.
	treeAtSnapshot := snap.ProcessTree
	syscallsAtSnapshot := totalSyscalls(snap.SyscallCounts)

	if syscallsAtSnapshot != 4 {
		t.Fatalf("snapshot recorded %d syscalls, want 4", syscallsAtSnapshot)
	}
	if !strings.Contains(treeAtSnapshot, "node(1001)") {
		t.Fatalf("snapshot process tree = %q, want it to contain %q", treeAtSnapshot, "node(1001)")
	}

	// Mutate the session after the snapshot was taken.
	session.AddProcess(collector.ProcessEvent{Pid: 2002, Comm: fixedComm("sh")})
	for _, id := range []uint32{257, 262} {
		session.AddSyscall(collector.SyscallEvent{Pid: 2002, SyscallID: id})
	}

	if got := totalSyscalls(snap.SyscallCounts); got != syscallsAtSnapshot {
		t.Errorf("snapshot syscall total changed from %d to %d after later writes; "+
			"the snapshot aliases live session state", syscallsAtSnapshot, got)
	}
	if snap.ProcessTree != treeAtSnapshot {
		t.Errorf("snapshot process tree changed after later writes")
	}
	if strings.Contains(snap.ProcessTree, "sh(2002)") {
		t.Errorf("snapshot process tree picked up a process added after the snapshot")
	}

	// A fresh snapshot must see the new writes -- otherwise the test above
	// could pass simply because Snapshot returns stale or empty data.
	fresh := session.Snapshot()
	if got := totalSyscalls(fresh.SyscallCounts); got != 6 {
		t.Errorf("fresh snapshot recorded %d syscalls, want 6", got)
	}
	if !strings.Contains(fresh.ProcessTree, "sh(2002)") {
		t.Errorf("fresh snapshot process tree = %q, want it to contain %q",
			fresh.ProcessTree, "sh(2002)")
	}
}

// TestSnapshotCopiesSessionIdentity asserts the scalar metadata BuildRecord
// depends on survives the snapshot.
func TestSnapshotCopiesSessionIdentity(t *testing.T) {
	session := NewSession(4242, "left-pad")
	session.Complete()

	snap := session.Snapshot()

	if snap.ID != session.ID {
		t.Errorf("snapshot ID = %q, want %q", snap.ID, session.ID)
	}
	if snap.PackageName != "left-pad" {
		t.Errorf("snapshot PackageName = %q, want %q", snap.PackageName, "left-pad")
	}
	if snap.EndTime.IsZero() {
		t.Error("snapshot EndTime is zero after Complete(); BuildRecord uses it for the timestamp")
	}
	if snap.StartTime.IsZero() {
		t.Error("snapshot StartTime is zero")
	}
}

// totalSyscalls sums every category, so the assertion does not depend on how
// Categorise maps a particular syscall number.
func totalSyscalls(counts map[features.SyscallCategory]int) int {
	total := 0
	for _, n := range counts {
		total += n
	}
	return total
}

// TestSnapshotIsRaceFreeUnderConcurrentWriters pins the concurrency guarantee
// of the new Snapshot boundary directly, rather than only through BuildRecord.
//
// This is a guard, not a TDD red: Snapshot takes s.mu from the moment it was
// written, so it passes immediately. It is kept because Snapshot's whole reason
// to exist is this guarantee -- if a future change reorders it, drops the lock,
// or returns a live map instead of a clone, this fails where a correctness-only
// test would not. The oracle is `go test -race`.
func TestSnapshotIsRaceFreeUnderConcurrentWriters(t *testing.T) {
	session := NewSession(303, "pkg")

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for w := 0; w < 6; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			pid := uint32(1000 + w)
			for i := 0; i < 300; i++ {
				select {
				case <-stop:
					return
				default:
				}
				session.AddProcess(collector.ProcessEvent{Pid: pid, Comm: fixedComm("node")})
				session.AddSyscall(collector.SyscallEvent{Pid: pid, SyscallID: uint32(257 + i%4)})
				session.AddFile(collector.FileEvent{Pid: pid, Flags: uint32(syscall.O_WRONLY)})
				session.AddTCP(collector.TCPEvent{Pid: pid, Sport: uint16(40000 + i%50), Dport: 4444})
			}
		}()
	}

	var last Snapshot
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			last = session.Snapshot()
			// Reading the cloned map must be safe even as writers continue.
			_ = totalSyscalls(last.SyscallCounts)
		}
	}()

	wg.Wait()
	close(stop)

	if last.ID != session.ID {
		t.Errorf("snapshot ID = %q, want %q", last.ID, session.ID)
	}
	final := session.Snapshot()
	if totalSyscalls(final.SyscallCounts) == 0 {
		t.Error("final snapshot recorded no syscalls; the writers did not run")
	}
}

// TestMarkCompleteOnceHasExactlyOneWinner asserts that when many goroutines
// call MarkCompleteOnce concurrently on the same Session, exactly one of them
// is told it won -- regardless of how many call it, or with what timedOut
// value.
//
// This is the arbitration primitive C3's fix depends on: the detector's two
// completion paths (normal exit, and the timeout callback on its own
// goroutine) each call this once and must never both proceed to unregister and
// send the session. The oracle is `go test -race`.
func TestMarkCompleteOnceHasExactlyOneWinner(t *testing.T) {
	const callers = 50

	session := NewSession(303, "pkg")

	var winners int32
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			if session.MarkCompleteOnce(i%2 == 0) {
				atomic.AddInt32(&winners, 1)
			}
		}()
	}
	wg.Wait()

	if winners != 1 {
		t.Errorf("MarkCompleteOnce reported %d winner(s) across %d concurrent callers, want exactly 1",
			winners, callers)
	}
}

// TestMarkCompleteOnceSetsStateAtomicallyWithTimedOut asserts that TimedOut,
// State and EndTime are all set together, by whichever call wins.
//
// Before this fix, TimedOut was written directly by the timeout callback with
// no lock at all -- a data race against any locked reader, independent of the
// double-completion bug itself.
func TestMarkCompleteOnceSetsStateAtomicallyWithTimedOut(t *testing.T) {
	tests := []struct {
		name         string
		timedOut     bool
		wantTimedOut bool
	}{
		{name: "normal exit wins", timedOut: false, wantTimedOut: false},
		{name: "timeout wins", timedOut: true, wantTimedOut: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := NewSession(303, "pkg")
			before := time.Now()

			won := session.MarkCompleteOnce(tt.timedOut)
			if !won {
				t.Fatal("first call to MarkCompleteOnce reported losing; want winning")
			}

			snap := session.Snapshot()
			if snap.TimedOut != tt.wantTimedOut {
				t.Errorf("TimedOut = %v, want %v", snap.TimedOut, tt.wantTimedOut)
			}
			if snap.State != SessionComplete {
				t.Errorf("State = %q, want %q", snap.State, SessionComplete)
			}
			if snap.EndTime.Before(before) {
				t.Errorf("EndTime = %v, want it no earlier than %v", snap.EndTime, before)
			}
		})
	}
}

// TestMarkCompleteOnceSecondCallDoesNotOverwriteTheFirstWinner asserts that a
// losing call cannot alter what the winner already recorded.
//
// This pins the exact scenario in AUDIT.md C3's "compounding" description: a
// session that completed via normal exit (TimedOut=false) must not have that
// silently flipped to true by a timeout callback that fires moments later on
// the very same session.
func TestMarkCompleteOnceSecondCallDoesNotOverwriteTheFirstWinner(t *testing.T) {
	session := NewSession(303, "pkg")

	if !session.MarkCompleteOnce(false) {
		t.Fatal("first call (normal exit) reported losing; want winning")
	}
	if session.MarkCompleteOnce(true) {
		t.Fatal("second call (timeout) reported winning; want losing")
	}

	snap := session.Snapshot()
	if snap.TimedOut {
		t.Error("TimedOut = true after a losing call overwrote the winner's false; " +
			"the losing call must be a no-op")
	}
}

// TestAddFileExposesSensitivePathThroughSnapshot is the seam where a real
// filename -- reaching userspace at all only since the pending_open fix --
// becomes verdict-facing evidence: opening a path that looks like an SSH
// private key must show up in Snapshot().Evidence.Paths.
func TestAddFileExposesSensitivePathThroughSnapshot(t *testing.T) {
	session := NewSession(404, "pkg")

	var evt collector.FileEvent
	evt.Pid = 404
	copy(evt.Filename[:], "/home/x/.ssh/id_rsa")
	evt.TimestampNs = 100

	session.AddFile(evt)

	snap := session.Snapshot()
	if !containsPathClass(snap.Evidence.Paths, features.PathClassSSHPrivateKey) {
		t.Fatalf("Snapshot().Evidence.Paths = %v, want it to contain PathClassSSHPrivateKey",
			snap.Evidence.Paths)
	}
}

func containsPathClass(paths []features.PathClass, want features.PathClass) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

// TestAddTCPNonRootEndpointOnlyFromNonRootPID confirms NonRootEndpoints only
// grows for connections whose PID is not the session's own npm root --
// NET-001 in the rule plan keys on exactly this distinction, since there is
// no DNS name to tell "the registry" from anything else the install
// contacted.
func TestAddTCPNonRootEndpointOnlyFromNonRootPID(t *testing.T) {
	session := NewSession(100, "pkg") // NpmPID = 100

	session.AddTCP(collector.TCPEvent{
		Pid: 100, Daddr: 0x0100007f, Dport: 443, TimestampNs: 1, // root PID
	})
	session.AddTCP(collector.TCPEvent{
		Pid: 200, Daddr: 0x0200007f, Dport: 8080, TimestampNs: 2, // child PID
	})

	snap := session.Snapshot()
	if len(snap.Evidence.NonRootEndpoints) != 1 {
		t.Fatalf("NonRootEndpoints = %v, want exactly one entry (the child PID's connection)",
			snap.Evidence.NonRootEndpoints)
	}
	if len(snap.Evidence.Endpoints) != 2 {
		t.Fatalf("Endpoints = %v, want both connections recorded", snap.Evidence.Endpoints)
	}
}

// TestSnapshotEvidenceRaceFreeUnderConcurrentWriters mirrors
// TestSnapshotIsRaceFreeUnderConcurrentWriters's shape, but drives events
// that actually produce evidence (a sensitive path, a shell-spawning
// process, a non-root TCP connection) and reads Snapshot().Evidence
// concurrently, at >=1000 iterations per writer.
//
// This test was verified, not just written, to actually close the race it
// targets: with AddFile/AddProcess/AddTCP's evidence hydration temporarily
// moved outside s.mu (and Snapshot's Evidence clone changed to alias the
// live collector instead of calling Snapshot()), `go test -race` reported
// a data race on this exact test within the first few iterations. That
// change was reverted -- this file contains only the correct,
// lock-disciplined version -- so "passes" here means the lock discipline is
// actually right, not that this run's goroutine interleaving happened not
// to trigger it.
func TestSnapshotEvidenceRaceFreeUnderConcurrentWriters(t *testing.T) {
	session := NewSession(999, "pkg") // NpmPID = 999, so pid 999 is root

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for w := 0; w < 6; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			pid := uint32(1000 + w) // every writer PID is non-root
			for i := 0; i < 1000; i++ {
				select {
				case <-stop:
					return
				default:
				}

				var fileEvt collector.FileEvent
				fileEvt.Pid = pid
				copy(fileEvt.Filename[:], "/home/x/.ssh/id_rsa")
				fileEvt.TimestampNs = uint64(i)
				session.AddFile(fileEvt)

				var procEvt collector.ProcessEvent
				procEvt.Pid = pid
				procEvt.Comm = fixedComm("bash")
				procEvt.TimestampNs = uint64(i)
				session.AddProcess(procEvt)

				session.AddTCP(collector.TCPEvent{
					Pid: pid, Daddr: uint32(i + 1), Dport: uint16(4000 + i%50), TimestampNs: uint64(i),
				})
			}
		}()
	}

	var last Snapshot
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			last = session.Snapshot()
			// Reading the cloned evidence must be safe even as writers
			// continue mutating the live collector concurrently.
			_ = len(last.Evidence.Paths)
			_ = len(last.Evidence.NonRootEndpoints)
		}
	}()

	wg.Wait()
	close(stop)

	final := session.Snapshot()
	if !containsPathClass(final.Evidence.Paths, features.PathClassSSHPrivateKey) {
		t.Error("final snapshot recorded no sensitive path; the writers did not run")
	}
	if len(final.Evidence.NonRootEndpoints) == 0 {
		t.Error("final snapshot recorded no non-root endpoints; the writers did not run")
	}
}
