package verdict

import "github.com/aniruddha/npm-ebpf-monitor/internal/features"

// Rule is one named, weighted signal in the verdict engine.
type Rule struct {
	ID        string
	Weight    int
	Decisive  bool   // fires -> Level is LevelMalicious regardless of total score
	Technique string // MITRE ATT&CK technique reference, e.g. "T1552.004"
	Eval      func(Input) (fired bool, evidence string)
}

// Input is the plain feature-typed view of one session that rules evaluate
// against.
//
// It is built from features.* types rather than reaching into a Session
// directly, so this package never imports internal/session: session hydrates
// evidence under its own lock, and internal/output builds an Input from
// session.Snapshot's contents. That keeps the dependency graph acyclic --
// verdict -> features, never verdict -> session.
type Input struct {
	Filetop   features.FiletopCounts
	Install   features.InstallFeatures
	DirCounts map[string]int
	TCP       features.TCPCounts
	Syscalls  features.SyscallFeatures
	Patterns  features.PatternCounts
	Evidence  features.Evidence
	Derived   Derived
}
