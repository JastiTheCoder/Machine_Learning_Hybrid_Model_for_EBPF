package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
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
		{"Pad2", unsafe.Offsetof(evt.Pad2), 268},
		{"TimestampNs", unsafe.Offsetof(evt.TimestampNs), 272},
	}
	for _, o := range offsets {
		if o.got != o.want {
			t.Errorf("offsetof(FileEvent.%s) = %d, want %d", o.name, o.got, o.want)
		}
	}
}

// TestFileEventBinaryReadDecodesTimestampFromRealWireBytes closes a gap
// TestFileEventLayoutMatchesBPFStruct's own offsets cannot: unsafe.Offsetof
// reports where TimestampNs lives in FileEvent's *Go-native* memory layout,
// which the Go compiler already pads to an 8-byte boundary the same way C
// does -- so that test passes regardless of whether binary.Read (the code
// Run actually calls, file_collector.go's Run) reproduces that same gap when
// decoding a byte stream. It does not: encoding/binary reads a struct
// field-by-field using each field's own size, with no allowance for the
// compiler-inserted alignment padding C leaves between "flags" (ends at
// wire offset 268) and "timestamp_ns" (starts at wire offset 272, per
// bpf/file_monitor.bpf.c's own layout comment) -- a 4-byte gap the Go struct
// has no field for. Without an explicit padding field, binary.Read consumes
// those 4 real timestamp bytes as if they were padding, and shifts every
// byte of the real 8-byte timestamp 4 bytes early, corrupting it.
//
// This test builds a raw 280-byte buffer with the timestamp at its real
// wire offset (272) and asserts the value FileCollector.Run's own decode
// path (binary.Read) recovers it exactly -- the decisive EXFIL-001 rule
// (internal/verdict/rules.go) depends entirely on FileEvent.TimestampNs
// being real, since it orders a sensitive read against an outbound connect.
func TestFileEventBinaryReadDecodesTimestampFromRealWireBytes(t *testing.T) {
	const wantTimestamp = uint64(0x0102030405060708)

	raw := make([]byte, 280)
	// pid @0..4, filename @4..260, dir_category @260, open_success @261,
	// pad[2] @262..264 -- left zero, none of it participates in this test.
	binary.LittleEndian.PutUint32(raw[264:268], 0x11223344) // flags
	// raw[268:272] is the C compiler's own alignment gap before the u64 --
	// filled with a recognizable non-zero pattern so a decode that
	// mistakenly starts reading the timestamp here, instead of at 272,
	// produces a value distinguishable from wantTimestamp rather than one
	// that could accidentally match by coincidence.
	copy(raw[268:272], []byte{0xAA, 0xAA, 0xAA, 0xAA})
	binary.LittleEndian.PutUint64(raw[272:280], wantTimestamp)

	var evt FileEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &evt); err != nil {
		t.Fatalf("binary.Read: %v", err)
	}

	if evt.TimestampNs != wantTimestamp {
		t.Errorf("TimestampNs = %#x, want %#x (decode did not land on the real wire offset 272)",
			evt.TimestampNs, wantTimestamp)
	}
	if evt.Flags != 0x11223344 {
		t.Errorf("Flags = %#x, want %#x", evt.Flags, 0x11223344)
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

// decodeFilename trims a NUL-terminated C string out of a fixed-size byte
// array, mirroring decodeComm's role for FileEvent.Filename.
func decodeFilename(b [256]byte) string {
	end := bytes.IndexByte(b[:], 0)
	if end == -1 {
		end = len(b)
	}
	return string(b[:end])
}

// TestFileCollectorReportsFilenameFromRealOpenat is the seam where the
// kernel probe meets userspace for the path itself, not just its flags.
// bpf/file_monitor.bpf.c's sys_enter_openat probe already reads the
// filename into a stack buffer to classify its directory -- but the exit
// probe (where the ring-buffer event is actually emitted) has historically
// discarded it, memset-ing FileEvent.Filename to all zero instead of
// carrying it through struct pending_open. Every consumer that wants to
// know *which* file was touched (not just which directory-category bucket
// it fell into) depends on this event carrying the real path.
//
// Requires root: it loads and attaches BPF programs.
func TestFileCollectorReportsFilenameFromRealOpenat(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

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

	pid := uint32(os.Getpid())
	ppid := uint32(os.Getppid())
	if err := trackedPids.Put(&pid, &ppid); err != nil {
		t.Fatalf("seed tracked_pids: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	path := filepath.Join(t.TempDir(), "filename-probe.txt")
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
				got := decodeFilename(evt.Filename)
				if got != path {
					t.Fatalf("FileEvent.Filename = %q, want %q (the enter probe's captured "+
						"path is not reaching the exit probe's emitted event)", got, path)
				}
				return
			}
		case <-deadline:
			t.Fatal("no O_WRONLY|O_CREAT file event observed for this process within 5s")
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
	Filename    [256]byte
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

// TestFileCollectorCountsDroppedEvents is the direct reproduction of
// AUDIT.md H5 for this collector: fills Events to its declared capacity so
// a genuine event has nowhere to land, then triggers one real tracked
// openat() and asserts the drop is counted rather than silently lost. This
// is a different drop mechanism from TestFileMonitorCountsFailedPendingOpensInserts
// above (a full userspace Go channel, not a full BPF map).
func TestFileCollectorCountsDroppedEvents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

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

	if got := fc.DroppedEvents(); got != 0 {
		t.Fatalf("DroppedEvents() = %d before any drop, want 0", got)
	}

	// Fill Events to its declared capacity so the next real event Run()
	// reads from the ring buffer has nowhere to go.
	for i := 0; i < cap(fc.Events); i++ {
		fc.Events <- FileEvent{}
	}

	pid := uint32(os.Getpid())
	ppid := uint32(os.Getppid())
	if err := trackedPids.Put(&pid, &ppid); err != nil {
		t.Fatalf("seed tracked_pids: %v", err)
	}

	path := filepath.Join(t.TempDir(), "drop-probe.txt")
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT, 0o644)
	if err != nil {
		t.Fatalf("openat probe file: %v", err)
	}
	syscall.Close(fd)

	deadline := time.Now().Add(5 * time.Second)
	for {
		if fc.DroppedEvents() > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("DroppedEvents() never rose above 0 within 5s after filling " +
				"Events to capacity and opening a real tracked file")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
