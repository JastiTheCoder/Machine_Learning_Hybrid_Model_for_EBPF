package verdict

import (
	"fmt"

	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
)

// netOpsRatioBaseline is the NET-003 threshold: network syscalls making up
// more than this fraction of a session's total syscalls is unusual for an
// ordinary npm install, where nearly all syscall volume is filesystem I/O.
// Recalibrated against the recaptured corpus in Stage 8.
const netOpsRatioBaseline = 0.15

// processOpsRatioBaseline is the PROC-003 threshold for
// process_ops / direct_dependencies.
//
// Calibrated against real data (Stage 8), not guessed: live captures of
// unmodified lodash/express/chalk/debug (no postinstall script at all) show
// ratios of 3.25-14.00 -- npm's own internal process spawning, nothing to
// do with the package. The project's own benign-test fixture (which does
// run a postinstall script, just a benign one) sits at 39.00 in the
// original captured corpus. reverse-shell-test, the one fixture that
// deliberately spawns many child processes as its payload, is the outlier
// at 123.00. The baseline sits between those two clusters -- above every
// observed benign ratio, below the one observed malicious outlier -- but
// with only one malicious data point this is a coarse cut, not a tight
// bound; see docs/new-features/001-verdict-scoring-engine/.
const processOpsRatioBaseline = 60.0

// RuleNET003 fires when network_ops / total_syscalls exceeds
// netOpsRatioBaseline -- a session spending an outsized share of its
// syscalls on the network, relative to the filesystem-heavy shape of a
// normal npm install.
var RuleNET003 = Rule{
	ID:        "NET-003",
	Weight:    10,
	Decisive:  false,
	Technique: "T1071",
	Eval: func(in Input) (bool, string) {
		if in.Derived.NetworkOpsRatio <= netOpsRatioBaseline {
			return false, ""
		}
		return true, fmt.Sprintf("network_ops ratio %.2f exceeds baseline %.2f",
			in.Derived.NetworkOpsRatio, netOpsRatioBaseline)
	},
}

// RuleCRED001 fires when the session read a known credential file --
// SSH private keys, cloud/registry/container credentials.
//
// The credential set lives in features.IsCredentialClass rather than here,
// so this rule and EvidenceCollector.AddPath's IndicatorCredentialRead
// cannot drift apart. Notably it excludes PathClassNpmrc, which npm reads on
// every ordinary install.
var RuleCRED001 = Rule{
	ID:        "CRED-001",
	Weight:    25,
	Decisive:  false,
	Technique: "T1552.004",
	Eval: func(in Input) (bool, string) {
		for _, class := range in.Evidence.Paths {
			if features.IsCredentialClass(class) {
				return true, fmt.Sprintf("read credential-class path (%d)", class)
			}
		}
		return false, ""
	},
}

// reconClasses are the PathClasses RuleRECON001 treats as host-recon reads.
var reconClasses = map[features.PathClass]bool{
	features.PathClassEtcPasswd: true,
	features.PathClassEtcShadow: true,
}

// RuleRECON001 fires when the session read a host-identity file such as
// /etc/passwd or /etc/shadow -- classic pre-exfiltration reconnaissance.
var RuleRECON001 = Rule{
	ID:        "RECON-001",
	Weight:    10,
	Decisive:  false,
	Technique: "T1082",
	Eval: func(in Input) (bool, string) {
		for _, class := range in.Evidence.Paths {
			if reconClasses[class] {
				return true, fmt.Sprintf("read host-recon path (%d)", class)
			}
		}
		return false, ""
	},
}

// RulePROC001 fires when the install script spawned a shell.
var RulePROC001 = Rule{
	ID:        "PROC-001",
	Weight:    20,
	Decisive:  false,
	Technique: "T1059.004",
	Eval: func(in Input) (bool, string) {
		for _, class := range in.Evidence.Argv {
			if class == features.ArgvClassShellSpawn {
				return true, "install script spawned a shell"
			}
		}
		return false, ""
	},
}

// RulePROC002 fires when the install script spawned a network tool
// (curl/wget/nc/...) -- a stronger, more specific signal than a shell spawn
// alone.
var RulePROC002 = Rule{
	ID:        "PROC-002",
	Weight:    15,
	Decisive:  false,
	Technique: "T1105",
	Eval: func(in Input) (bool, string) {
		for _, class := range in.Evidence.Argv {
			if class == features.ArgvClassNetworkTool {
				return true, "install script spawned a network tool"
			}
		}
		return false, ""
	},
}

// RulePROC003 fires when process_ops / direct_dependencies exceeds
// processOpsRatioBaseline -- a small install spawning as many processes as a
// much larger one is unusual.
var RulePROC003 = Rule{
	ID:        "PROC-003",
	Weight:    10,
	Decisive:  false,
	Technique: "T1059",
	Eval: func(in Input) (bool, string) {
		if in.Derived.ProcessOpsRatio <= processOpsRatioBaseline {
			return false, ""
		}
		return true, fmt.Sprintf("process_ops ratio %.2f exceeds baseline %.2f",
			in.Derived.ProcessOpsRatio, processOpsRatioBaseline)
	},
}

// RuleNET001 fires when an outbound connection came from a PID that is not
// the session's own npm root process -- the install script spawned
// something else that then opened a socket of its own.
var RuleNET001 = Rule{
	ID:        "NET-001",
	Weight:    15,
	Decisive:  false,
	Technique: "T1071",
	Eval: func(in Input) (bool, string) {
		if len(in.Evidence.NonRootEndpoints) == 0 {
			return false, ""
		}
		return true, fmt.Sprintf("outbound connection from a non-root PID to %s",
			in.Evidence.NonRootEndpoints[0])
	},
}

// wellKnownPorts are the remote ports RuleNET002 treats as unremarkable for
// an npm install talking to a package registry over plain HTTP or TLS.
var wellKnownPorts = map[string]bool{"80": true, "443": true}

// RuleNET002 fires when any remote endpoint uses a port outside {80, 443}.
var RuleNET002 = Rule{
	ID:        "NET-002",
	Weight:    10,
	Decisive:  false,
	Technique: "T1571",
	Eval: func(in Input) (bool, string) {
		for _, ep := range in.Evidence.Endpoints {
			_, port, ok := splitEndpointPort(ep)
			if ok && !wellKnownPorts[port] {
				return true, fmt.Sprintf("connection to non-standard port (%s)", ep)
			}
		}
		return false, ""
	},
}

// splitEndpointPort splits an "ip:port" string as formatted by
// features.FormatEndpoint.
func splitEndpointPort(endpoint string) (host, port string, ok bool) {
	for i := len(endpoint) - 1; i >= 0; i-- {
		if endpoint[i] == ':' {
			return endpoint[:i], endpoint[i+1:], true
		}
	}
	return "", "", false
}

// RuleDROP001 fires when the session touched a temp directory and had more
// than one distinct writing process -- a secondary payload-dropping step,
// as distinct from npm's own single extraction write.
//
// Threshold raised from ">0" to ">1" writers in Stage 8 calibration: all
// four real-world benign captures (lodash, express, chalk, debug) touch a
// temp dir and show exactly one writer -- npm's own node process
// extracting the downloaded tarball -- which made ">0" fire on every
// install regardless of maliciousness. Requiring a second, independent
// writer process is a materially stronger signal that something beyond
// npm's own extraction wrote into the temp dir.
var RuleDROP001 = Rule{
	ID:        "DROP-001",
	Weight:    15,
	Decisive:  false,
	Technique: "T1105",
	Eval: func(in Input) (bool, string) {
		if in.DirCounts["temp_dir_access"] <= 0 {
			return false, ""
		}
		if in.Filetop.WriteProcesses <= 1 {
			return false, ""
		}
		return true, fmt.Sprintf("wrote into a temp directory (%d accesses, %d writers)",
			in.DirCounts["temp_dir_access"], in.Filetop.WriteProcesses)
	},
}

// RuleOBF001 fires when the install script's argv matched an obfuscation
// shape -- base64 decoding or dynamic eval.
var RuleOBF001 = Rule{
	ID:        "OBF-001",
	Weight:    10,
	Decisive:  false,
	Technique: "T1027",
	Eval: func(in Input) (bool, string) {
		for _, class := range in.Evidence.Argv {
			if class == features.ArgvClassBase64Decode || class == features.ArgvClassEvalExec {
				return true, "obfuscated/dynamic execution shape in argv"
			}
		}
		return false, ""
	},
}

// RulePERSIST001 fires when the session wrote into a persistence-shaped
// location -- a cron.d drop-in, a systemd unit, or a shell rc file -- as
// distinct from merely reading one. Decisive: an install script planting a
// scheduled or startup execution point for itself has no benign
// explanation.
var RulePERSIST001 = Rule{
	ID:        "PERSIST-001",
	Weight:    50,
	Decisive:  true,
	Technique: "T1053",
	Eval: func(in Input) (bool, string) {
		if len(in.Evidence.PersistenceWrites) == 0 {
			return false, ""
		}
		return true, fmt.Sprintf("wrote into a persistence-class location (%d)",
			in.Evidence.PersistenceWrites[0])
	},
}

// RuleEXFIL001 fires when a credential-class read was observed strictly
// before an outbound connection -- the read-then-send shape of actual
// exfiltration, as opposed to either fact occurring alone or in the
// opposite order. Decisive: this ordering has no benign explanation for an
// npm install script.
//
// It reads IndicatorCredentialRead, not IndicatorSensitiveRead. The broad
// indicator is marked for all thirteen PathClasses including PathClassNpmrc,
// which npm reads on every install before contacting the registry -- so
// consuming it here banded ordinary unmodified installs malicious on nothing
// but their own config read (NEW_AUDIT.md NC1). Stage 8 had already narrowed
// CRED-001 for exactly this reason; the narrowing simply never reached the
// indicator its sibling rule depends on.
var RuleEXFIL001 = Rule{
	ID:        "EXFIL-001",
	Weight:    50,
	Decisive:  true,
	Technique: "T1552.004",
	Eval: func(in Input) (bool, string) {
		readAt, readOK := in.Evidence.FirstSeen[features.IndicatorCredentialRead]
		connectAt, connectOK := in.Evidence.FirstSeen[features.IndicatorOutboundConnect]
		if !readOK || !connectOK {
			return false, ""
		}
		if readAt >= connectAt {
			return false, ""
		}
		return true, fmt.Sprintf("credential read at t=%d preceded outbound connect at t=%d", readAt, connectAt)
	},
}
