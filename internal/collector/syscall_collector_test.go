package collector

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestSyscallCollectorCountsDroppedEvents is the direct reproduction of
// AUDIT.md H5 for this collector: fills Events to its declared capacity so
// a genuine event has nowhere to land, then marks this process tracked
// (which alone generates a steady stream of real raw_syscalls/sys_enter
// events, since Go's own runtime is constantly making syscalls) and asserts
// the resulting drops are counted rather than silently lost.
func TestSyscallCollectorCountsDroppedEvents(t *testing.T) {
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

	sc, err := NewSyscallCollector(trackedPids)
	if err != nil {
		t.Fatalf("NewSyscallCollector: %v", err)
	}
	defer sc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sc.Run(ctx)
	time.Sleep(200 * time.Millisecond) // let the tracepoint attach

	if got := sc.DroppedEvents(); got != 0 {
		t.Fatalf("DroppedEvents() = %d before any drop, want 0", got)
	}

	// Fill Events to its declared capacity so real events Run() reads from
	// the ring buffer have nowhere to go.
	for i := 0; i < cap(sc.Events); i++ {
		sc.Events <- SyscallEvent{}
	}

	// Marking this process tracked is enough: the Go runtime itself makes a
	// continuous stream of real syscalls (scheduler, GC, timers), each of
	// which raw_syscalls/sys_enter reports for a tracked pid.
	pid := uint32(os.Getpid())
	ppid := uint32(os.Getppid())
	if err := trackedPids.Put(&pid, &ppid); err != nil {
		t.Fatalf("seed tracked_pids: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if sc.DroppedEvents() > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("DroppedEvents() never rose above 0 within 5s after filling " +
				"Events to capacity and marking this process tracked")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
