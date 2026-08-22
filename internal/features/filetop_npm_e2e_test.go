package features

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aniruddha/npm-ebpf-monitor/internal/collector"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// descendants returns root plus every process transitively parented by it, so
// the test can track the whole npm process tree without relying on
// ProcessTracer's fork propagation.
func descendants(root int) []int {
	parent := map[int]int{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// ppid is field 4, but comm (field 2) can itself contain spaces and
		// parens, so scan past the final ')' before splitting.
		end := strings.LastIndex(string(b), ")")
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(b)[end+1:])
		if len(fields) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		parent[pid] = ppid
	}

	out := []int{root}
	for pid := range parent {
		for p, hops := pid, 0; p > 1 && hops < 64; hops++ {
			p = parent[p]
			if p == root {
				out = append(out, pid)
				break
			}
		}
	}
	return out
}

// newNpmFixture builds a throwaway npm project whose only dependency is a
// local directory, so the install does real filesystem work without needing
// network access.
func newNpmFixture(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	dep := filepath.Join(dir, "localdep")
	if err := os.MkdirAll(dep, 0o755); err != nil {
		t.Fatalf("mkdir dep: %v", err)
	}

	write := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(filepath.Join(dep, "package.json"), `{"name":"localdep","version":"1.0.0","main":"index.js"}`)
	write(filepath.Join(dep, "index.js"), "module.exports = 42;\n")
	write(filepath.Join(dir, "package.json"), `{"name":"e2e-fixture","version":"1.0.0"}`)

	return dir
}

// TestFiletopAggregatorCountsWritersDuringRealNpmInstall drives the complete
// C1 chain -- openat() in the kernel, file_monitor.bpf.c, the ring buffer,
// FileCollector decoding, FiletopAggregator -- against a real npm install, and
// asserts that write_processes is non-zero.
//
// The same event stream is aggregated a second time with Flags forced to 0 to
// reproduce exactly what the kernel used to emit. That copy must report
// write_processes == 0, which pins down the fix as the thing responsible for
// the difference rather than any incidental change in npm's behaviour.
func TestFiletopAggregatorCountsWritersDuringRealNpmInstall(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
	projDir := newNpmFixture(t)

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("memlock: %v", err)
	}

	trackedPids, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 4096,
	})
	if err != nil {
		t.Fatalf("tracked_pids: %v", err)
	}
	defer trackedPids.Close()

	fc, err := collector.NewFileCollector(trackedPids)
	if err != nil {
		t.Fatalf("NewFileCollector: %v", err)
	}
	defer fc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fc.Run(ctx)
	time.Sleep(300 * time.Millisecond) // let the tracepoints attach

	fixed := NewFiletopAggregator()
	preFix := NewFiletopAggregator()
	var mu sync.Mutex
	var total, withFlags int

	stopDrain := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			var evt collector.FileEvent
			select {
			case <-stopDrain:
				return
			case evt = <-fc.Events:
			}

			mu.Lock()
			total++
			if evt.Flags != 0 {
				withFlags++
			}
			fixed.Add(evt)

			zeroed := evt
			zeroed.Flags = 0 // what the kernel used to always send
			preFix.Add(zeroed)
			mu.Unlock()
		}
	}()

	cmd := exec.Command("npm", "install", "./localdep", "--no-audit", "--no-fund")
	cmd.Dir = projDir
	if err := cmd.Start(); err != nil {
		t.Fatalf("npm start: %v", err)
	}
	root := cmd.Process.Pid

	stopSeed := make(chan struct{})
	seeded := make(chan struct{})
	go func() {
		defer close(seeded)
		one := uint32(1)
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stopSeed:
				return
			case <-tick.C:
				for _, pid := range descendants(root) {
					k := uint32(pid)
					_ = trackedPids.Update(&k, &one, ebpf.UpdateAny)
				}
			}
		}
	}()

	npmErr := cmd.Wait()
	close(stopSeed)
	<-seeded
	time.Sleep(1500 * time.Millisecond) // drain in-flight ring buffer events
	close(stopDrain)
	<-drained
	cancel()

	if npmErr != nil {
		t.Logf("npm exited with %v (still evaluating captured events)", npmErr)
	}

	mu.Lock()
	defer mu.Unlock()
	after := fixed.Snapshot()
	before := preFix.Snapshot()

	t.Logf("file events captured: %d (with non-zero flags: %d)", total, withFlags)
	t.Logf("PRE-FIX  (flags always 0): read_processes=%d write_processes=%d file_access_processes=%d",
		before.ReadProcesses, before.WriteProcesses, before.FileAccessProcesses)
	t.Logf("POST-FIX (real flags):     read_processes=%d write_processes=%d file_access_processes=%d",
		after.ReadProcesses, after.WriteProcesses, after.FileAccessProcesses)

	if total == 0 {
		t.Fatal("no file events captured at all")
	}
	if before.WriteProcesses != 0 {
		t.Errorf("pre-fix control: WriteProcesses = %d, want 0", before.WriteProcesses)
	}
	if after.WriteProcesses == 0 {
		t.Error("post-fix WriteProcesses = 0; npm install writes files, so this must be > 0")
	}
}
