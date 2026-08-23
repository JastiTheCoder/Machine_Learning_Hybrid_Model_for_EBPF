package collector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestProcessEventLayoutMatchesBPFStruct(t *testing.T) {
	var evt ProcessEvent

	if got, want := unsafe.Sizeof(evt), uintptr(296); got != want {
		t.Fatalf("unsafe.Sizeof(ProcessEvent{}) = %d, want %d", got, want)
	}

	tests := []struct {
		name   string
		offset uintptr
		want   uintptr
	}{
		{name: "Pid", offset: unsafe.Offsetof(evt.Pid), want: 0},
		{name: "Ppid", offset: unsafe.Offsetof(evt.Ppid), want: 4},
		{name: "Comm", offset: unsafe.Offsetof(evt.Comm), want: 8},
		{name: "Args", offset: unsafe.Offsetof(evt.Args), want: 24},
		{name: "TimestampNs", offset: unsafe.Offsetof(evt.TimestampNs), want: 280},
		{name: "IsNpmRelated", offset: unsafe.Offsetof(evt.IsNpmRelated), want: 288},
		{name: "EventType", offset: unsafe.Offsetof(evt.EventType), want: 292},
	}

	for _, tt := range tests {
		if tt.offset != tt.want {
			t.Fatalf("unsafe.Offsetof(ProcessEvent.%s) = %d, want %d", tt.name, tt.offset, tt.want)
		}
	}
}

// selfComm returns this process's comm, which is what a forked child inherits
// until it execs.
func selfComm(t *testing.T) string {
	t.Helper()

	b, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatalf("read /proc/self/comm: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func requireRoot(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
}

// TestNewProcessCollectorLoadsAndAttaches asserts that the ProcessTracer BPF
// programs verify, load and attach against the kernel actually running this
// test.
//
// This is the narrowest possible statement of "the monitor can start": main.go
// calls NewProcessCollector during startup and exits if it returns an error.
func TestNewProcessCollectorLoadsAndAttaches(t *testing.T) {
	requireRoot(t)

	pc, err := NewProcessCollector()
	if err != nil {
		t.Fatalf("NewProcessCollector() = %v, want nil", err)
	}
	t.Cleanup(func() { pc.Close() })
}

// TestProcessCollectorReportsForkOfTrackedProcess asserts that forking a child
// from a tracked process produces a FORK event carrying the child's pid, the
// forking task's pid, and the comm the child inherited.
//
// Loading is necessary but not sufficient: a program that loads because a
// field read was deleted would still pass the test above while silently
// emitting empty comms. This pins the data the fork handler must report.
//
// Seeds only this process's pid (its tgid). Earlier this test seeded every
// thread id under /proc/self/task, because exec.Command's fork could run on
// any Go runtime thread and the fork handler looked up ctx->parent_pid -- the
// calling thread's tid -- against a tgid-keyed map. That was a workaround for
// the bug fixed in docs/fix-fork-tgid-lookup/: the handler now resolves the
// tgid via bpf_get_current_pid_tgid(), so seeding the tgid alone is correct
// regardless of which OS thread the runtime happens to fork from. See
// TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess below for
// the direct, deterministic reproduction of that bug.
func TestProcessCollectorReportsForkOfTrackedProcess(t *testing.T) {
	requireRoot(t)

	pc, err := NewProcessCollector()
	if err != nil {
		t.Fatalf("NewProcessCollector: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go pc.Run(ctx)
	time.Sleep(300 * time.Millisecond) // let the tracepoints attach

	tracked := pc.TrackedPidsMap()
	one := uint32(1)
	selfPID := uint32(os.Getpid())
	if err := tracked.Update(&selfPID, &one, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed tgid %d: %v", selfPID, err)
	}

	wantComm := selfComm(t)

	cmd := exec.Command("/bin/sleep", "0.2")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	childPID := uint32(cmd.Process.Pid)
	t.Cleanup(func() { _ = cmd.Wait() })

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("no FORK event for child pid %d within 5s", childPID)
		case evt := <-pc.Events:
			if evt.EventType != 1 || evt.Pid != childPID {
				continue
			}

			if evt.Ppid == 0 {
				t.Errorf("FORK event Ppid = 0, want the forking task's pid")
			}
			if got := decodeComm(evt.Comm); got != wantComm {
				t.Errorf("FORK event Comm = %q, want %q", got, wantComm)
			}
			return
		}
	}
}

// decodeComm trims the NUL padding from a fixed-width comm field.
func decodeComm(comm [16]byte) string {
	if i := bytes.IndexByte(comm[:], 0); i >= 0 {
		return string(comm[:i])
	}
	return string(comm[:])
}

// requireCC skips the test if no C compiler is available, and returns its path.
func requireCC(t *testing.T) string {
	t.Helper()

	for _, name := range []string{"cc", "gcc"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	t.Skip("no C compiler (cc/gcc) available")
	return ""
}

// compileForkFromThreadHelper builds testdata/fork_from_thread.c into a fresh
// temp binary and returns its path.
func compileForkFromThreadHelper(t *testing.T) string {
	t.Helper()

	cc := requireCC(t)
	bin := filepath.Join(t.TempDir(), "fork_from_thread")
	cmd := exec.Command(cc, "-O0", "-pthread", "-o", bin, "testdata/fork_from_thread.c")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile testdata/fork_from_thread.c: %v\n%s", err, out)
	}
	return bin
}

// TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess is the
// direct reproduction of the audited finding: "the fork handler filters a
// thread id against a tgid-keyed map ... for a multithreaded process forking
// from a non-leader thread the lookup misses and the fork event -- and that
// child's whole subtree -- is silently dropped."
//
// Unlike TestProcessCollectorReportsForkOfTrackedProcess above, this test
// seeds tracked_pids with ONLY the tracked process's tgid -- the way every
// other consumer of that map populates and reads it (see is_tracked(tgid) in
// syscall_tracer.bpf.c, file_monitor.bpf.c, tcp_monitor.bpf.c, and the
// sched_process_exit handler's own comment: "tracked_pids stores tgids, not
// individual thread ids"). It then forks from a thread that is deterministically
// NOT that tgid's leader, using a small C helper rather than relying on
// whichever OS thread the Go runtime happens to schedule the fork onto.
//
// If the fork handler looks up ctx->parent_pid (the calling thread's tid), the
// lookup misses and no FORK event is ever produced for the child -- the defect
// as audited. If it looks up the current tgid instead, the fork is correctly
// attributed to the tracked process regardless of which of its threads issued
// the syscall.
func TestProcessCollectorReportsForkFromNonLeaderThreadOfTrackedProcess(t *testing.T) {
	requireRoot(t)
	helper := compileForkFromThreadHelper(t)

	pc, err := NewProcessCollector()
	if err != nil {
		t.Fatalf("NewProcessCollector: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go pc.Run(ctx)
	time.Sleep(300 * time.Millisecond) // let the tracepoints attach

	cmd := exec.Command(helper)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Wait() })

	reader := bufio.NewScanner(stdout)

	if !reader.Scan() {
		t.Fatalf("read PARENT_PID line: %v", reader.Err())
	}
	parentPID, err := parseHelperLine(reader.Text(), "PARENT_PID=")
	if err != nil {
		t.Fatalf("parse %q: %v", reader.Text(), err)
	}

	// Seed ONLY the tgid, matching how the exec handler and every downstream
	// consumer populate and read this map. This is the crux of the test: it
	// deliberately does NOT reproduce the workaround used by
	// TestProcessCollectorReportsForkOfTrackedProcess above.
	tracked := pc.TrackedPidsMap()
	one := uint32(1)
	if err := tracked.Update(&parentPID, &one, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed tgid %d: %v", parentPID, err)
	}

	if !reader.Scan() {
		t.Fatalf("read CHILD_PID line: %v", reader.Err())
	}
	childPID, err := parseHelperLine(reader.Text(), "CHILD_PID=")
	if err != nil {
		t.Fatalf("parse %q: %v", reader.Text(), err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("no FORK event for child pid %d within 5s (forked from a non-leader "+
				"thread of tracked tgid %d)", childPID, parentPID)
		case evt := <-pc.Events:
			if evt.EventType != 1 || evt.Pid != childPID {
				continue
			}
			if evt.Ppid != parentPID {
				t.Errorf("FORK event Ppid = %d, want %d (the tracked process's tgid)", evt.Ppid, parentPID)
			}
			return
		}
	}
}

// parseHelperLine extracts the uint32 pid from a "KEY=<n>" line produced by
// testdata/fork_from_thread.c.
func parseHelperLine(line, prefix string) (uint32, error) {
	if !strings.HasPrefix(line, prefix) {
		return 0, fmt.Errorf("line %q does not start with %q", line, prefix)
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(line, prefix), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

// TestProcessCollectorCountsDroppedEvents is the direct reproduction of
// AUDIT.md H5 for this collector: fills Events toward its declared capacity
// so a genuine event has nowhere to land, then triggers one real FORK event
// and asserts the resulting drop is counted rather than silently lost.
//
// Unlike the other four collectors' equivalent tests, this one cannot use an
// absolute "0 before, then something after" assertion, and its fill loop
// cannot use a plain blocking send. process_tracer.bpf.c's sys_enter_execve
// handler is NOT gated by is_tracked() -- it emits an event for every
// execve() on the entire machine, tracked or not, since tracking itself
// begins at exec. Under real load (confirmed by this test hanging for 10
// minutes under `go test ./...`'s concurrent subprocess spawning before this
// fix) Run()'s own goroutine can already be pushing real, ambient,
// system-wide events into Events concurrently with this test's setup -- so
// a plain blocking send can permanently deadlock (nothing ever drains
// Events in this test), and a fixed "DroppedEvents() == 0" baseline can be
// wrong before the test does anything at all. Both are handled here: the
// fill uses a non-blocking select, and the assertion is relative
// (after > before), the same pattern already used for the BPF-map version
// of this counter in TestFileMonitorCountsFailedPendingOpensInserts (H2).
//
// This is itself a real finding, not just a test-authoring wrinkle: on a
// busy machine, ProcessCollector.Events can fill with unrelated system exec
// noise and start dropping before any npm install even begins -- the
// sharpest version of H5 among the five collectors, precisely because this
// one has no is_tracked() gate at the kernel boundary at all.
func TestProcessCollectorCountsDroppedEvents(t *testing.T) {
	requireRoot(t)

	pc, err := NewProcessCollector()
	if err != nil {
		t.Fatalf("NewProcessCollector: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go pc.Run(ctx)
	time.Sleep(300 * time.Millisecond) // let the tracepoints attach

	before := pc.DroppedEvents()

	// Top Events up toward its declared capacity without ever blocking:
	// Run()'s own goroutine may already be concurrently pushing real,
	// unrelated exec events into the same channel (see the doc comment
	// above), and nothing in this test ever drains Events, so a plain
	// blocking send here could deadlock permanently rather than merely losing
	// the race for a slot.
	for i := 0; i < cap(pc.Events); i++ {
		select {
		case pc.Events <- ProcessEvent{}:
		default:
			// Events is already full -- either this loop or real ambient
			// exec traffic got there first. Either way the channel is at
			// capacity, which is all this test needs.
		}
	}

	tracked := pc.TrackedPidsMap()
	one := uint32(1)
	selfPID := uint32(os.Getpid())
	if err := tracked.Update(&selfPID, &one, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed tgid %d: %v", selfPID, err)
	}

	cmd := exec.Command("/bin/sleep", "0.2")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Wait() })

	deadline := time.Now().Add(5 * time.Second)
	for {
		if pc.DroppedEvents() > before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("DroppedEvents() never rose above its before-test value (%d) within 5s "+
				"after filling Events toward capacity and forking a real tracked child", before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
