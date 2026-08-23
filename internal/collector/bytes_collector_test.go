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

// TestBytesCollectorCountsDroppedEvents is the direct reproduction of
// AUDIT.md H5 for this collector: fills Events to its declared capacity so
// a genuine event has nowhere to land, then drives a real loopback TCP send
// from this (tracked) process -- triggering kprobe/tcp_sendmsg for real --
// and asserts the resulting drops are counted rather than silently lost.
func TestBytesCollectorCountsDroppedEvents(t *testing.T) {
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

	bc, err := NewBytesCollector(trackedPids)
	if err != nil {
		t.Fatalf("NewBytesCollector: %v", err)
	}
	defer bc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bc.Run(ctx)
	time.Sleep(200 * time.Millisecond) // let the kprobes attach

	if got := bc.DroppedEvents(); got != 0 {
		t.Fatalf("DroppedEvents() = %d before any drop, want 0", got)
	}

	// Fill Events to its declared capacity so real events Run() reads from
	// the ring buffer have nowhere to go.
	for i := 0; i < cap(bc.Events); i++ {
		bc.Events <- BytesEvent{}
	}

	pid := uint32(os.Getpid())
	ppid := uint32(os.Getppid())
	if err := trackedPids.Put(&pid, &ppid); err != nil {
		t.Fatalf("seed tracked_pids: %v", err)
	}

	// A real loopback send from this tracked process: tcp_sendmsg fires in
	// this process's own context, which is all kprobe/tcp_sendmsg needs.
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
			go func() {
				buf := make([]byte, 64)
				for {
					if _, err := conn.Read(buf); err != nil {
						conn.Close()
						return
					}
				}
			}()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello, world")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if bc.DroppedEvents() > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("DroppedEvents() never rose above 0 within 5s after filling " +
				"Events to capacity and sending a real tracked TCP write")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
