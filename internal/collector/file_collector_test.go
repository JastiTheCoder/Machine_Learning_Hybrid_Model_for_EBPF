package collector

import (
	"context"
	"os"
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
