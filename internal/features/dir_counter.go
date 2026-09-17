// Package features provides higher-level analysis on top of raw eBPF events.
package features

// Directory category constants mirror the C DIR_* defines in
// bpf/file_monitor.bpf.c and the DirectoryCategory iota in
// internal/collector/file_collector.go.
//
// They are duplicated here (unexported) to keep the dependency graph clean:
// the features layer must not import the collector layer.
const (
	dirOther   uint8 = 0
	dirRoot    uint8 = 1
	dirTemp    uint8 = 2
	dirHome    uint8 = 3
	dirUserLib uint8 = 4
	dirSys     uint8 = 5
	dirEtc     uint8 = 6
)

// DirCounts accumulates directory-access counts for a single npm-install
// session.  Each field corresponds to one of the DIR_* categories emitted
// by the file_monitor BPF program.
type DirCounts struct {
	Root    int
	Temp    int
	Home    int
	UserLib int
	Sys     int
	Etc     int
	Other   int
}

// Add increments the counter that corresponds to category.
// The value must match one of the DIR_* constants defined in
// bpf/file_monitor.bpf.c; any unrecognised value is counted as Other.
func (dc *DirCounts) Add(category uint8) {
	switch category {
	case dirRoot:
		dc.Root++
	case dirTemp:
		dc.Temp++
	case dirHome:
		dc.Home++
	case dirUserLib:
		dc.UserLib++
	case dirSys:
		dc.Sys++
	case dirEtc:
		dc.Etc++
	default: // dirOther (0) and any future/unknown value
		dc.Other++
	}
}

// ToMap returns a map of the 7 directory-access counts.
//
// .ssh/.aws paths are classified as DIR_OTHER by the BPF layer, so they are
// counted here only as other_dir_access. That was originally done to hold the
// exported vector at the 36 features QUT-DV25 defines; that constraint is
// gone (ml_analysis/QUT_RETIREMENT.md), but the BPF-side categorisation is
// deliberately left alone.
//
// Credential-path signal is no longer lost as a result: SensitiveAccess
// surfaces it per-class from the userspace path classifier, which is both
// more granular than a directory bucket and does not require a BPF change.
// Widening the BPF categories would only duplicate it.
func (dc *DirCounts) ToMap() map[string]int {
	return map[string]int{
		"root_dir_access":  dc.Root,
		"temp_dir_access":  dc.Temp,
		"home_dir_access":  dc.Home,
		"user_dir_access":  dc.UserLib,
		"sys_dir_access":   dc.Sys,
		"etc_dir_access":   dc.Etc,
		"other_dir_access": dc.Other,
	}
}
