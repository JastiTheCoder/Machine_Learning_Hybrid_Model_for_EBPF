package collector

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestFileEventLayoutMatchesBPFStruct pins the userspace decode contract for
// struct file_event in bpf/file_monitor.bpf.c.  binary.Read decodes the ring
// buffer sample field-by-field in declaration order, so any drift between the
// C struct and this Go struct silently misaligns every field after the change.
// Flags sitting at offset 264 is what makes the open-mode features decodable.
func TestFileEventLayoutMatchesBPFStruct(t *testing.T) {
	var evt FileEvent

	if got, want := unsafe.Sizeof(evt), uintptr(280); got != want {
		t.Fatalf("unsafe.Sizeof(FileEvent{}) = %d, want %d", got, want)
	}

	offsets := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Pid", unsafe.Offsetof(evt.Pid), 0},
		{"Filename", unsafe.Offsetof(evt.Filename), 4},
		{"DirCategory", unsafe.Offsetof(evt.DirCategory), 260},
		{"OpenSuccess", unsafe.Offsetof(evt.OpenSuccess), 261},
		{"Pad", unsafe.Offsetof(evt.Pad), 262},
		{"Flags", unsafe.Offsetof(evt.Flags), 264},
		{"TimestampNs", unsafe.Offsetof(evt.TimestampNs), 272},
	}
	for _, o := range offsets {
		if o.got != o.want {
			t.Errorf("offsetof(FileEvent.%s) = %d, want %d", o.name, o.got, o.want)
		}
	}
}

// TestFileCollectorReportsOpenFlagsFromRealOpenat is the seam where the kernel
// probe meets userspace: a tracked process performs a real openat() with a
// known access mode, and the FileCollector must surface that mode on the
// emitted event.  The open-mode features (read_processes / write_processes)
// are derived entirely from FileEvent.Flags, so if the probe does not carry
// the caller's flags across the enter/exit boundary those features are
// unrecoverable no matter what userspace does with them.
//
// Requires root: it loads and attaches BPF programs.
func TestFileCollectorReportsOpenFlagsFromRealOpenat(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	// Stand in for the map the ProcessTracer normally owns.  Must match the
	// tracked_pids definition in file_monitor.bpf.c exactly for
	// MapReplacements to accept it.
	trackedPids, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 4096,
	})
	if err != nil {
		t.Fatalf("create tracked_pids map: %v", err)
	}
	defer trackedPids.Close()

	collector, err := NewFileCollector(trackedPids)
	if err != nil {
		t.Fatalf("NewFileCollector: %v", err)
	}
	defer collector.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go collector.Run(ctx)

	// Mark this process as tracked so the probe emits our opens.
	pid := uint32(os.Getpid())
	ppid := uint32(os.Getppid())
	if err := trackedPids.Put(&pid, &ppid); err != nil {
		t.Fatalf("seed tracked_pids: %v", err)
	}

	// Give the tracepoints a moment to start delivering before we probe.
	time.Sleep(200 * time.Millisecond)

	// The behaviour under test: one real write-and-create open.
	path := filepath.Join(t.TempDir(), "open-flags-probe.txt")
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT, 0o644)
	if err != nil {
		t.Fatalf("openat probe file: %v", err)
	}
	syscall.Close(fd)

	deadline := time.After(5 * time.Second)
	for {
		select {
		case evt := <-collector.Events:
			if evt.Pid != pid {
				continue
			}
			if evt.Flags&syscall.O_ACCMODE == syscall.O_WRONLY && evt.Flags&syscall.O_CREAT != 0 {
				return // observed the write-create open with its flags intact
			}
		case <-deadline:
			t.Fatal("no O_WRONLY|O_CREAT file event observed for this process within 5s; " +
				"open flags are not reaching userspace")
		}
	}
}

// pendingOpenValue mirrors struct pending_open in bpf/file_monitor.bpf.c. It
// exists only so ebpf.Map.Put/Lookup have a value of the right size and
// layout for pending_opens; the tests below never inspect its fields.
type pendingOpenValue struct {
	Pid         uint32
	Flags       uint32
	DirCategory uint8
	Pad         [3]byte
}

// compileBlockInOpenatHelper builds testdata/block_in_openat.c into a fresh
// temp binary and returns its path.
func compileBlockInOpenatHelper(t *testing.T) string {
	t.Helper()

	cc := requireCC(t)
	bin := filepath.Join(t.TempDir(), "block_in_openat")
	cmd := exec.Command(cc, "-O0", "-o", bin, "testdata/block_in_openat.c")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile testdata/block_in_openat.c: %v\n%s", err, out)
	}
	return bin
}

// TestFileCollectorClearsPendingOpensEntryWhenKilledMidOpenat targets AUDIT.md
// H2's leak: "if a tracked process is SIGKILLed while blocked inside
// openat(), sys_exit_openat never fires and the entry is never removed."
//
// testdata/block_in_openat.c blocks in a real open() on a FIFO with no
// writer -- deterministic, not timing-dependent -- so the test can be certain
// the helper is genuinely parked inside the syscall before it is killed,
// rather than hoping a real open() on some ordinary file happens to still be
// in flight at the moment of the kill.
//
// IMPORTANT -- an empirical correction to H2's premise, found while building
// this test: on this kernel, sys_exit_openat's own tracepoint DOES still fire
// for this scenario (a fatal signal delivered during an interruptible sleep),
// with ctx->ret carrying the interrupted return code -- so it cleans up the
// entry itself, and this test passes even with the new sched_process_exit
// cleanup hook (below) fully disabled. Checked directly: reproducing the
// literal leak this test is named for required disabling BOTH cleanup paths
// at once (evidence/red-all-cleanup-paths-disabled.txt); with either one
// alone, the entry is still removed (evidence/isolation-*-alone-sufficient.txt).
// See docs/bugs-fixed/fix-pending-opens-leak/ for the full isolation matrix.
//
// The hook is kept anyway as a low-cost backstop for a thread that dies
// without ever returning from openat() at all -- e.g. blocked in an
// uninterruptible (D-state) wait on an unresponsive filesystem, which SIGKILL
// alone cannot unblock -- a scenario this test cannot reproduce portably but
// which the audit's underlying concern (an unbounded, unrecoverable map leak
// during a long capture) still applies to.
func TestFileCollectorClearsPendingOpensEntryWhenKilledMidOpenat(t *testing.T) {
	requireRoot(t)
	helperPath := compileBlockInOpenatHelper(t)

	trackedPids, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 4096,
	})
	if err != nil {
		t.Fatalf("create tracked_pids map: %v", err)
	}
	defer trackedPids.Close()

	fc, err := NewFileCollector(trackedPids)
	if err != nil {
		t.Fatalf("NewFileCollector: %v", err)
	}
	defer fc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fc.Run(ctx)
	time.Sleep(200 * time.Millisecond) // let the tracepoints attach

	fifoPath := filepath.Join(t.TempDir(), "block.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	cmd := exec.Command(helperPath, fifoPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
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
		t.Fatalf("read PID line: %v", reader.Err())
	}
	helperPID, err := parseHelperLine(reader.Text(), "PID=")
	if err != nil {
		t.Fatalf("parse %q: %v", reader.Text(), err)
	}

	// Mark the helper tracked before releasing it, so sys_enter_openat's
	// is_tracked() check passes for its upcoming open() call.
	ppid := uint32(os.Getpid())
	if err := trackedPids.Put(&helperPID, &ppid); err != nil {
		t.Fatalf("seed tracked_pids: %v", err)
	}

	// Release the helper: it now calls open() on the FIFO and blocks.
	if _, err := stdin.Write([]byte{'x'}); err != nil {
		t.Fatalf("release helper: %v", err)
	}

	// pending_opens is keyed by pid_tgid; block_in_openat.c is single-threaded,
	// so its tid equals its tgid and pid_tgid == (pid<<32)|pid.
	key := (uint64(helperPID) << 32) | uint64(helperPID)

	// Confirm the entry actually appears before killing anything -- otherwise
	// a false pass here could mean the helper never really reached openat(),
	// not that the leak is fixed.
	var val pendingOpenValue
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := fc.objs.PendingOpens.Lookup(&key, &val); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending_opens never gained an entry for pid %d; "+
				"the helper may not have reached openat()", helperPID)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill helper pid %d: %v", helperPID, err)
	}
	_ = cmd.Wait()

	deadline = time.Now().Add(2 * time.Second)
	for {
		err := fc.objs.PendingOpens.Lookup(&key, &val)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return // fixed: the entry was cleaned up on process exit
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending_opens still holds an entry for killed pid %d 2s later; "+
				"the entry leaked (AUDIT.md H2)", helperPID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestFileMonitorCountsFailedPendingOpensInserts is the direct reproduction
// of the other half of AUDIT.md H2: "bpf_map_update_elem's return value is
// never checked at the insert site, so under sustained leakage the map
// silently starts dropping new file events with no signal to userspace."
//
// Fills pending_opens to its 4096-entry bound with synthetic keys reserved
// well outside any real pid_tgid range, then performs one real, tracked
// openat() -- now guaranteed to find the map full and fail its own insert --
// and asserts the failure is counted rather than silently swallowed.
func TestFileMonitorCountsFailedPendingOpensInserts(t *testing.T) {
	requireRoot(t)

	trackedPids, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 4096,
	})
	if err != nil {
		t.Fatalf("create tracked_pids map: %v", err)
	}
	defer trackedPids.Close()

	fc, err := NewFileCollector(trackedPids)
	if err != nil {
		t.Fatalf("NewFileCollector: %v", err)
	}
	defer fc.Close()

	// Reserve the map to capacity with keys no real pid_tgid can ever equal:
	// the upper 32 bits would have to be a live pid, and Linux's pid_max is
	// far below 0xFFFFFFFF.
	var filler pendingOpenValue
	for i := uint64(0); i < 4096; i++ {
		key := (uint64(0xFFFFFFFF) << 32) | i
		if err := fc.objs.PendingOpens.Put(&key, &filler); err != nil {
			t.Fatalf("pre-fill pending_opens entry %d: %v", i, err)
		}
	}

	before, err := fc.PendingOpensInsertFailures()
	if err != nil {
		t.Fatalf("PendingOpensInsertFailures (before): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fc.Run(ctx)
	time.Sleep(200 * time.Millisecond) // let the tracepoints attach

	pid := uint32(os.Getpid())
	ppid := uint32(os.Getppid())
	if err := trackedPids.Put(&pid, &ppid); err != nil {
		t.Fatalf("seed tracked_pids: %v", err)
	}

	path := filepath.Join(t.TempDir(), "insert-failure-probe.txt")
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT, 0o644)
	if err != nil {
		t.Fatalf("openat probe file: %v", err)
	}
	syscall.Close(fd)

	deadline := time.Now().Add(2 * time.Second)
	for {
		after, err := fc.PendingOpensInsertFailures()
		if err != nil {
			t.Fatalf("PendingOpensInsertFailures (after): %v", err)
		}
		if after > before {
			return // counted: fixed
		}
		if time.Now().After(deadline) {
			t.Fatalf("file_monitor_stats[pending_opens insert failed] did not increase "+
				"(before=%d, after=%d) after a real openat() with pending_opens full; "+
				"the failed insert went uncounted (AUDIT.md H2)", before, after)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
