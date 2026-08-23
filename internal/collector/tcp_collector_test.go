package collector

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestTcpCollectorCountsDroppedEvents is the direct reproduction of
// AUDIT.md H5 for this collector: fills Events to its declared capacity so
// a genuine event has nowhere to land, then drives a real loopback TCP
// connection from this (tracked) process -- producing real state-transition
// events via tcp_monitor.bpf.c's own sock_to_pid bridging -- and asserts the
// resulting drops are counted rather than silently lost.
func TestTcpCollectorCountsDroppedEvents(t *testing.T) {
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

	tc, err := NewTcpCollector(trackedPids)
	if err != nil {
		t.Fatalf("NewTcpCollector: %v", err)
	}
	defer tc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tc.Run(ctx)
	time.Sleep(200 * time.Millisecond) // let the tracepoint attach

	if got := tc.DroppedEvents(); got != 0 {
		t.Fatalf("DroppedEvents() = %d before any drop, want 0", got)
	}

	// Fill Events to its declared capacity so real events Run() reads from
	// the ring buffer have nowhere to go.
	for i := 0; i < cap(tc.Events); i++ {
		tc.Events <- TCPEvent{}
	}

	pid := uint32(os.Getpid())
	ppid := uint32(os.Getppid())
	if err := trackedPids.Put(&pid, &ppid); err != nil {
		t.Fatalf("seed tracked_pids: %v", err)
	}

	// A real loopback connection from this tracked process: connect()
	// registers skaddr -> tgid in sock_to_pid at SYN_SENT (process context),
	// and subsequent transitions (e.g. ESTABLISHED, CLOSE) are attributed via
	// that map regardless of which kernel context processes them.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if tc.DroppedEvents() > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("DroppedEvents() never rose above 0 within 5s after filling " +
				"Events to capacity and driving a real tracked TCP connection")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
