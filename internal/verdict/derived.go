package verdict

import "github.com/aniruddha/npm-ebpf-monitor/internal/features"

// Derived holds install-size-normalized ratios.
//
// Raw counts scale with install size -- a 400-dependency install legitimately
// produces far more syscalls than a 1-dependency one -- so a rule that needs
// to be portable across install sizes compares a ratio against a baseline
// instead of a raw count. Fields are added here as the rules that need them
// are implemented (Stage 6), not speculatively.
type Derived struct {
	// NetworkOpsRatio is NetworkOps / total syscalls observed in the
	// session. Zero when no syscalls were observed at all, rather than NaN.
	NetworkOpsRatio float64

	// ProcessOpsRatio is ProcessOps / direct dependency count. A 1-package
	// install spawning as many processes as a 400-package one is unusual;
	// dividing by direct dependencies is what makes this portable across
	// install sizes. Zero when there are no direct dependencies, rather
	// than +Inf.
	ProcessOpsRatio float64
}

// NewDerived computes install-size-normalized ratios from raw syscall
// counts and the install's direct dependency count. Both ratios are zero
// (rather than NaN or +Inf) when their denominator is zero.
func NewDerived(syscalls features.SyscallFeatures, directDependencies int) Derived {
	total := syscalls.IoOps + syscalls.FileOps + syscalls.NetworkOps +
		syscalls.TimeOps + syscalls.SecurityOps + syscalls.ProcessOps + syscalls.UnknownOps

	var d Derived
	if total > 0 {
		d.NetworkOpsRatio = float64(syscalls.NetworkOps) / float64(total)
	}
	if directDependencies > 0 {
		d.ProcessOpsRatio = float64(syscalls.ProcessOps) / float64(directDependencies)
	}
	return d
}
