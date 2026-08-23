package features

import (
	"syscall"
	"testing"
)

// TestEvidenceCollectorDeduplicatesRepeatedPaths confirms that repeatedly
// opening the same sensitive path collapses to one PathClass entry rather
// than growing without bound for the lifetime of a long-running install.
func TestEvidenceCollectorDeduplicatesRepeatedPaths(t *testing.T) {
	c := NewEvidenceCollector()

	for i := 0; i < 5000; i++ {
		c.AddPath("/home/x/.ssh/id_rsa", syscall.O_RDONLY, uint64(i))
	}

	got := c.Snapshot()
	if len(got.Paths) != 1 {
		t.Fatalf("Paths = %v, want exactly one entry", got.Paths)
	}
	if got.Paths[0] != PathClassSSHPrivateKey {
		t.Errorf("Paths[0] = %v, want %v", got.Paths[0], PathClassSSHPrivateKey)
	}
}

// TestEvidenceCollectorCapsEndpoints confirms the endpoint cap holds and is
// honestly surfaced: feeding more distinct endpoints than the cap retains
// only evidenceCap of them, and Truncated flips to true so a consumer knows
// evidence was dropped rather than silently trusting an incomplete set.
func TestEvidenceCollectorCapsEndpoints(t *testing.T) {
	c := NewEvidenceCollector()

	for i := 0; i < 100; i++ {
		c.AddEndpoint(syntheticEndpoint(i), true, uint64(i))
	}

	got := c.Snapshot()
	if len(got.Endpoints) != evidenceCap {
		t.Errorf("len(Endpoints) = %d, want %d", len(got.Endpoints), evidenceCap)
	}
	if !got.Truncated {
		t.Error("Truncated = false, want true after exceeding the endpoint cap")
	}
}

func syntheticEndpoint(i int) string {
	// Cheap distinct "ip:port" values; the exact values don't matter, only
	// that all 100 are distinct from each other.
	return "203.0.113." + string(rune('0'+i%10)) + ":" + string(rune('0'+i/10))
}

// TestEvidenceCollectorFirstSeenRecordsEarliestTimestamp confirms firstSeen
// takes a minimum across every call for a given indicator, not the value
// from whichever call happened to land first -- events genuinely arrive out
// of timestamp order here, since five independent ring-buffer readers feed
// one session (AUDIT.md H4).
func TestEvidenceCollectorFirstSeenRecordsEarliestTimestamp(t *testing.T) {
	c := NewEvidenceCollector()

	// Deliberately out of order: 500 arrives before 100.
	c.AddPath("/home/x/.ssh/id_rsa", syscall.O_RDONLY, 500)
	c.AddPath("/home/x/.aws/credentials", syscall.O_RDONLY, 100)
	c.AddPath("/home/x/.npmrc", syscall.O_RDONLY, 300)

	got := c.Snapshot()
	earliest, ok := got.FirstSeen[IndicatorSensitiveRead]
	if !ok {
		t.Fatal("FirstSeen[IndicatorSensitiveRead] not recorded")
	}
	if earliest != 100 {
		t.Errorf("FirstSeen[IndicatorSensitiveRead] = %d, want 100 (the earliest of 500, 100, 300)", earliest)
	}
}

// TestEvidenceCollectorSnapshotIsCloned confirms mutating the collector
// after taking a Snapshot cannot mutate a snapshot a caller is still
// holding -- the same clone-on-read contract session.Session's other
// aggregators rely on.
func TestEvidenceCollectorSnapshotIsCloned(t *testing.T) {
	c := NewEvidenceCollector()
	c.AddPath("/home/x/.ssh/id_rsa", syscall.O_RDONLY, 1)
	c.AddEndpoint("203.0.113.5:443", true, 1)

	held := c.Snapshot()

	// Mutate the collector after the snapshot was taken.
	c.AddPath("/home/x/.aws/credentials", syscall.O_RDONLY, 2)
	c.AddEndpoint("203.0.113.6:443", true, 2)
	for i := 0; i < 100; i++ {
		c.AddEndpoint(syntheticEndpoint(i+1000), true, uint64(i))
	}

	if len(held.Paths) != 1 {
		t.Errorf("held.Paths changed after later mutation: %v", held.Paths)
	}
	if len(held.Endpoints) != 1 {
		t.Errorf("held.Endpoints changed after later mutation: %v", held.Endpoints)
	}
	if held.Truncated {
		t.Error("held.Truncated flipped to true after later mutation -- snapshot was not cloned")
	}
}

// TestEvidenceCollectorNonRootEndpointsOnlyTrackNonRoot confirms AddEndpoint
// only grows NonRootEndpoints (and marks IndicatorNonRootOutbound) when
// isRoot is false, and leaves both untouched for the session's own root PID.
func TestEvidenceCollectorNonRootEndpointsOnlyTrackNonRoot(t *testing.T) {
	c := NewEvidenceCollector()

	c.AddEndpoint("203.0.113.1:443", true, 1)  // root PID
	c.AddEndpoint("203.0.113.2:443", false, 2) // child PID

	got := c.Snapshot()
	if len(got.Endpoints) != 2 {
		t.Fatalf("Endpoints = %v, want both endpoints recorded", got.Endpoints)
	}
	if len(got.NonRootEndpoints) != 1 || got.NonRootEndpoints[0] != "203.0.113.2:443" {
		t.Errorf("NonRootEndpoints = %v, want exactly [203.0.113.2:443]", got.NonRootEndpoints)
	}
	if _, ok := got.FirstSeen[IndicatorNonRootOutbound]; !ok {
		t.Error("FirstSeen[IndicatorNonRootOutbound] not recorded for the non-root endpoint")
	}
}

// TestEvidenceCollectorTracksPersistenceWritesOnlyForWriteOpens confirms
// PersistenceWrites (which PERSIST-001 in the verdict rule set relies on)
// only grows when a persistence-location path was actually opened for
// writing -- a read of ~/.bashrc (a shell innocuously sourcing its own
// config) must not look identical to writing a backdoor into it.
func TestEvidenceCollectorTracksPersistenceWritesOnlyForWriteOpens(t *testing.T) {
	c := NewEvidenceCollector()

	c.AddPath("/home/x/.bashrc", syscall.O_RDONLY, 1)  // read: not a persistence write
	c.AddPath("/etc/cron.d/evil", syscall.O_WRONLY, 2) // write: is one
	c.AddPath("/etc/passwd", syscall.O_WRONLY, 3)      // write, but not a persistence class at all

	got := c.Snapshot()
	if len(got.PersistenceWrites) != 1 {
		t.Fatalf("PersistenceWrites = %v, want exactly one entry", got.PersistenceWrites)
	}
	if got.PersistenceWrites[0] != PathClassCronDir {
		t.Errorf("PersistenceWrites[0] = %v, want %v", got.PersistenceWrites[0], PathClassCronDir)
	}
	if _, ok := got.FirstSeen[IndicatorPersistenceWrite]; !ok {
		t.Error("FirstSeen[IndicatorPersistenceWrite] not recorded")
	}

	// O_CREAT with an otherwise read-only access mode is still a write, by
	// the same convention FiletopAggregator.Add already uses.
	c2 := NewEvidenceCollector()
	c2.AddPath("/home/x/.zshrc", syscall.O_RDONLY|syscall.O_CREAT, 1)
	got2 := c2.Snapshot()
	if len(got2.PersistenceWrites) != 1 {
		t.Fatalf("PersistenceWrites (O_CREAT case) = %v, want exactly one entry", got2.PersistenceWrites)
	}
}
