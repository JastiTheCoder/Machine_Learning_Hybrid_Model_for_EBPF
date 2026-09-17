package features

import (
	"syscall"
	"testing"
)

// TestSensitiveAccessEmpty verifies a session with no security-relevant
// evidence produces an all-zero vector rather than absent fields -- the CSV
// export has no way to represent "missing", so every column must be present
// and explicitly zero.
func TestSensitiveAccessEmpty(t *testing.T) {
	got := BuildSensitiveAccess(NewEvidenceCollector().Snapshot())

	for i, v := range got.Values() {
		if v != 0 {
			t.Errorf("empty evidence: column %q = %d, want 0",
				SensitiveAccessColumns()[i], v)
		}
	}
}

// TestSensitiveAccessColumnsMatchValues is the invariant the CSV export
// depends on. If a field is added to the struct and to Values() but not to
// SensitiveAccessColumns(), every column after the insertion point silently
// shifts by one and the exported dataset is misaligned with its own header.
func TestSensitiveAccessColumnsMatchValues(t *testing.T) {
	cols := SensitiveAccessColumns()
	vals := SensitiveAccess{}.Values()

	if len(cols) != len(vals) {
		t.Fatalf("SensitiveAccessColumns() has %d entries but Values() has %d; "+
			"a field was added to one and not the other", len(cols), len(vals))
	}

	seen := make(map[string]bool, len(cols))
	for _, c := range cols {
		if seen[c] {
			t.Errorf("duplicate column name %q", c)
		}
		seen[c] = true
	}
}

// TestSensitiveAccessCredentialRead checks that reading an SSH private key
// sets both the specific flag and the credential aggregate. This is the case
// that motivated the whole struct: ssh-reader-test previously produced a
// feature vector with no indication a key had been read.
func TestSensitiveAccessCredentialRead(t *testing.T) {
	ec := NewEvidenceCollector()
	ec.AddPath("/home/user/.ssh/id_rsa", syscall.O_RDONLY, 100)

	got := BuildSensitiveAccess(ec.Snapshot())

	if got.SSHPrivateKeyRead != 1 {
		t.Errorf("SSHPrivateKeyRead = %d, want 1", got.SSHPrivateKeyRead)
	}
	if got.CredentialClassRead != 1 {
		t.Errorf("CredentialClassRead = %d, want 1", got.CredentialClassRead)
	}
	if got.AWSCredentialsRead != 0 {
		t.Errorf("AWSCredentialsRead = %d, want 0 (no AWS path was read)", got.AWSCredentialsRead)
	}
}

// TestSensitiveAccessNpmrcIsNotCredential guards the distinction NC1 turned
// on. npm reads .npmrc on every ordinary install, so it must be visible as
// its own feature without counting toward the credential aggregate.
func TestSensitiveAccessNpmrcIsNotCredential(t *testing.T) {
	ec := NewEvidenceCollector()
	ec.AddPath("/home/user/.npmrc", syscall.O_RDONLY, 100)

	got := BuildSensitiveAccess(ec.Snapshot())

	if got.NpmrcRead != 1 {
		t.Errorf("NpmrcRead = %d, want 1", got.NpmrcRead)
	}
	if got.CredentialClassRead != 0 {
		t.Errorf("CredentialClassRead = %d, want 0: .npmrc is read by every "+
			"ordinary install and must not count as a credential", got.CredentialClassRead)
	}
}

// TestSensitiveAccessOrdering covers the temporal features. Aggregate counts
// cannot distinguish read-then-send from send-then-read, and only the former
// is exfiltration.
func TestSensitiveAccessOrdering(t *testing.T) {
	tests := []struct {
		name               string
		readAt             uint64
		connectAt          uint64
		wantCredBeforeConn int
		wantSensBeforeConn int
	}{
		{"read strictly before connect", 100, 200, 1, 1},
		{"connect strictly before read", 200, 100, 0, 0},
		{"same timestamp is not precedence", 100, 100, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ec := NewEvidenceCollector()
			ec.AddPath("/home/user/.ssh/id_rsa", syscall.O_RDONLY, tt.readAt)
			ec.AddEndpoint("10.0.0.1:443", true, tt.connectAt)

			got := BuildSensitiveAccess(ec.Snapshot())

			if got.CredentialReadBeforeConnect != tt.wantCredBeforeConn {
				t.Errorf("CredentialReadBeforeConnect = %d, want %d",
					got.CredentialReadBeforeConnect, tt.wantCredBeforeConn)
			}
			if got.SensitiveReadBeforeConnect != tt.wantSensBeforeConn {
				t.Errorf("SensitiveReadBeforeConnect = %d, want %d",
					got.SensitiveReadBeforeConnect, tt.wantSensBeforeConn)
			}
		})
	}
}

// TestSensitiveAccessOrderingNeedsBothEvents verifies that a read with no
// connection (or the reverse) is not treated as an ordering.
func TestSensitiveAccessOrderingNeedsBothEvents(t *testing.T) {
	ec := NewEvidenceCollector()
	ec.AddPath("/home/user/.ssh/id_rsa", syscall.O_RDONLY, 100)

	got := BuildSensitiveAccess(ec.Snapshot())

	if got.CredentialReadBeforeConnect != 0 {
		t.Errorf("CredentialReadBeforeConnect = %d, want 0: nothing connected outbound",
			got.CredentialReadBeforeConnect)
	}
}

// TestSensitiveAccessNpmrcDoesNotSetCredentialOrdering is the feature-layer
// half of the NC1 regression. The broad ordering may fire on a .npmrc read,
// but the credential ordering -- the one EXFIL-001 consumes -- must not.
func TestSensitiveAccessNpmrcDoesNotSetCredentialOrdering(t *testing.T) {
	ec := NewEvidenceCollector()
	ec.AddPath("/home/user/.npmrc", syscall.O_RDONLY, 100)
	ec.AddEndpoint("104.16.0.1:443", true, 200)

	got := BuildSensitiveAccess(ec.Snapshot())

	if got.CredentialReadBeforeConnect != 0 {
		t.Errorf("CredentialReadBeforeConnect = %d, want 0: an ordinary install "+
			"reading its own .npmrc before reaching the registry is not exfiltration",
			got.CredentialReadBeforeConnect)
	}
	if got.SensitiveReadBeforeConnect != 1 {
		t.Errorf("SensitiveReadBeforeConnect = %d, want 1: the broad ordering "+
			"should still be recorded as a weak feature", got.SensitiveReadBeforeConnect)
	}
}

// TestSensitiveAccessPersistenceWrites checks that writes into startup
// locations are counted, and that a read of the same location is not.
func TestSensitiveAccessPersistenceWrites(t *testing.T) {
	read := NewEvidenceCollector()
	read.AddPath("/home/user/.bashrc", syscall.O_RDONLY, 100)
	if got := BuildSensitiveAccess(read.Snapshot()); got.PersistenceWrites != 0 {
		t.Errorf("reading ~/.bashrc: PersistenceWrites = %d, want 0", got.PersistenceWrites)
	}
	if got := BuildSensitiveAccess(read.Snapshot()); got.ShellRCRead != 1 {
		t.Errorf("reading ~/.bashrc: ShellRCRead = %d, want 1", got.ShellRCRead)
	}

	write := NewEvidenceCollector()
	write.AddPath("/home/user/.bashrc", syscall.O_WRONLY, 100)
	if got := BuildSensitiveAccess(write.Snapshot()); got.PersistenceWrites != 1 {
		t.Errorf("writing ~/.bashrc: PersistenceWrites = %d, want 1", got.PersistenceWrites)
	}
}

// TestSensitiveAccessEndpointCounts verifies endpoint totals, including the
// non-root subset NET-001 keys on.
func TestSensitiveAccessEndpointCounts(t *testing.T) {
	ec := NewEvidenceCollector()
	ec.AddEndpoint("10.0.0.1:443", true, 100)
	ec.AddEndpoint("10.0.0.2:80", false, 200)
	ec.AddEndpoint("10.0.0.2:80", false, 300) // duplicate, must dedupe

	got := BuildSensitiveAccess(ec.Snapshot())

	if got.DistinctEndpoints != 2 {
		t.Errorf("DistinctEndpoints = %d, want 2", got.DistinctEndpoints)
	}
	if got.NonRootEndpoints != 1 {
		t.Errorf("NonRootEndpoints = %d, want 1", got.NonRootEndpoints)
	}
}
