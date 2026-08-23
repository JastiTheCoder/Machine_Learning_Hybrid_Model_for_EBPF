package verdict

import (
	"testing"

	"github.com/aniruddha/npm-ebpf-monitor/internal/features"
)

// fire is a small helper: evaluate a single rule against input and report
// whether it fired.
func fire(t *testing.T, r Rule, in Input) (bool, string) {
	t.Helper()
	return r.Eval(in)
}

func TestRuleCRED001(t *testing.T) {
	positive := Input{Evidence: features.Evidence{Paths: []features.PathClass{features.PathClassAWSCredentials}}}
	if got, _ := fire(t, RuleCRED001, positive); !got {
		t.Error("RuleCRED001 did not fire on a read of .aws/credentials")
	}

	negative := Input{Evidence: features.Evidence{Paths: []features.PathClass{features.PathClassDotEnv}}}
	if got, _ := fire(t, RuleCRED001, negative); got {
		t.Error("RuleCRED001 fired on a .env read, which is not a credential-file class it covers")
	}

	// Near-miss: .npmrc is deliberately excluded (Stage 8 calibration) --
	// npm reads it on every ordinary install, script or no script.
	npmrc := Input{Evidence: features.Evidence{Paths: []features.PathClass{features.PathClassNpmrc}}}
	if got, _ := fire(t, RuleCRED001, npmrc); got {
		t.Error("RuleCRED001 fired on .npmrc, which npm reads on every ordinary install")
	}
}

func TestRuleRECON001(t *testing.T) {
	positive := Input{Evidence: features.Evidence{Paths: []features.PathClass{features.PathClassEtcShadow}}}
	if got, _ := fire(t, RuleRECON001, positive); !got {
		t.Error("RuleRECON001 did not fire on a read of /etc/shadow")
	}

	negative := Input{Evidence: features.Evidence{Paths: []features.PathClass{features.PathClassGitConfig}}}
	if got, _ := fire(t, RuleRECON001, negative); got {
		t.Error("RuleRECON001 fired on a gitconfig read, which is not a recon-class path")
	}
}

func TestRulePROC001(t *testing.T) {
	positive := Input{Evidence: features.Evidence{Argv: []features.ArgvClass{features.ArgvClassShellSpawn}}}
	if got, _ := fire(t, RulePROC001, positive); !got {
		t.Error("RulePROC001 did not fire on a shell spawn")
	}

	negative := Input{Evidence: features.Evidence{Argv: []features.ArgvClass{features.ArgvClassEvalExec}}}
	if got, _ := fire(t, RulePROC001, negative); got {
		t.Error("RulePROC001 fired on an eval-exec argv class, not a shell spawn")
	}
}

func TestRulePROC002(t *testing.T) {
	positive := Input{Evidence: features.Evidence{Argv: []features.ArgvClass{features.ArgvClassNetworkTool}}}
	if got, _ := fire(t, RulePROC002, positive); !got {
		t.Error("RulePROC002 did not fire on a spawned network tool")
	}

	negative := Input{Evidence: features.Evidence{Argv: []features.ArgvClass{features.ArgvClassShellSpawn}}}
	if got, _ := fire(t, RulePROC002, negative); got {
		t.Error("RulePROC002 fired on a shell spawn, not a network tool")
	}
}

func TestRulePROC003(t *testing.T) {
	positive := Input{Derived: Derived{ProcessOpsRatio: 123.0}}
	if got, _ := fire(t, RulePROC003, positive); !got {
		t.Error("RulePROC003 did not fire above the process_ops/direct_dependencies baseline")
	}

	negative := Input{Derived: Derived{ProcessOpsRatio: 0.5}}
	if got, _ := fire(t, RulePROC003, negative); got {
		t.Error("RulePROC003 fired below the baseline")
	}

	// Near-miss: a ratio in the observed real-world benign range (up to
	// ~39.0, per Stage 8's captures) must stay below the raised baseline.
	nearMiss := Input{Derived: Derived{ProcessOpsRatio: 39.0}}
	if got, _ := fire(t, RulePROC003, nearMiss); got {
		t.Error("RulePROC003 fired on a ratio within the observed benign range")
	}
}

func TestRuleNET001(t *testing.T) {
	positive := Input{Evidence: features.Evidence{NonRootEndpoints: []string{"203.0.113.5:443"}}}
	if got, _ := fire(t, RuleNET001, positive); !got {
		t.Error("RuleNET001 did not fire on a non-root outbound connection")
	}

	negative := Input{Evidence: features.Evidence{Endpoints: []string{"203.0.113.5:443"}}}
	if got, _ := fire(t, RuleNET001, negative); got {
		t.Error("RuleNET001 fired on an endpoint that was only ever the root PID's own connection")
	}
}

func TestRuleNET002(t *testing.T) {
	positive := Input{Evidence: features.Evidence{Endpoints: []string{"203.0.113.5:31337"}}}
	if got, _ := fire(t, RuleNET002, positive); !got {
		t.Error("RuleNET002 did not fire on a remote port outside {80, 443}")
	}

	negative := Input{Evidence: features.Evidence{Endpoints: []string{"203.0.113.5:443", "203.0.113.6:80"}}}
	if got, _ := fire(t, RuleNET002, negative); got {
		t.Error("RuleNET002 fired even though every endpoint was port 80 or 443")
	}
}

func TestRuleDROP001(t *testing.T) {
	positive := Input{
		DirCounts: map[string]int{"temp_dir_access": 3},
		Filetop:   features.FiletopCounts{WriteProcesses: 2},
	}
	if got, _ := fire(t, RuleDROP001, positive); !got {
		t.Error("RuleDROP001 did not fire on temp-dir access plus two writers")
	}

	negative := Input{
		DirCounts: map[string]int{"temp_dir_access": 3},
		Filetop:   features.FiletopCounts{WriteProcesses: 0},
	}
	if got, _ := fire(t, RuleDROP001, negative); got {
		t.Error("RuleDROP001 fired on temp-dir access with no writer at all")
	}

	// Near-miss: exactly one writer is npm's own tarball-extraction write,
	// observed on every real-world benign install captured in Stage 8 --
	// this must not fire on its own.
	oneWriter := Input{
		DirCounts: map[string]int{"temp_dir_access": 3},
		Filetop:   features.FiletopCounts{WriteProcesses: 1},
	}
	if got, _ := fire(t, RuleDROP001, oneWriter); got {
		t.Error("RuleDROP001 fired on exactly one writer, which is npm's own extraction write")
	}
}

func TestRuleOBF001(t *testing.T) {
	positive := Input{Evidence: features.Evidence{Argv: []features.ArgvClass{features.ArgvClassBase64Decode}}}
	if got, _ := fire(t, RuleOBF001, positive); !got {
		t.Error("RuleOBF001 did not fire on a base64-decode argv class")
	}

	negative := Input{Evidence: features.Evidence{Argv: []features.ArgvClass{features.ArgvClassChmodExec}}}
	if got, _ := fire(t, RuleOBF001, negative); got {
		t.Error("RuleOBF001 fired on a chmod-exec argv class, which is not an obfuscation shape")
	}
}

func TestRulePERSIST001(t *testing.T) {
	positive := Input{Evidence: features.Evidence{PersistenceWrites: []features.PathClass{features.PathClassCronDir}}}
	if got, _ := fire(t, RulePERSIST001, positive); !got {
		t.Error("RulePERSIST001 did not fire on a cron.d write")
	}
	if !RulePERSIST001.Decisive {
		t.Error("RulePERSIST001.Decisive = false, want true")
	}

	// A mere read of a persistence-shaped path (not a write) must not fire
	// this -- that distinction is exactly what EvidenceCollector.AddPath's
	// isWriteOpen check exists for.
	negative := Input{Evidence: features.Evidence{Paths: []features.PathClass{features.PathClassCronDir}}}
	if got, _ := fire(t, RulePERSIST001, negative); got {
		t.Error("RulePERSIST001 fired on Paths (a read) rather than PersistenceWrites")
	}
}

// TestRuleEXFIL001 pins the ordering correlation in both directions: a
// credential-class read strictly before an outbound connection fires it;
// the reverse order, and either fact alone, does not.
func TestRuleEXFIL001(t *testing.T) {
	if !RuleEXFIL001.Decisive {
		t.Fatal("RuleEXFIL001.Decisive = false, want true")
	}

	readThenConnect := Input{Evidence: features.Evidence{FirstSeen: map[features.Indicator]uint64{
		features.IndicatorSensitiveRead:   100,
		features.IndicatorOutboundConnect: 200,
	}}}
	if got, _ := fire(t, RuleEXFIL001, readThenConnect); !got {
		t.Error("RuleEXFIL001 did not fire when a sensitive read preceded an outbound connect")
	}

	connectThenRead := Input{Evidence: features.Evidence{FirstSeen: map[features.Indicator]uint64{
		features.IndicatorOutboundConnect: 100,
		features.IndicatorSensitiveRead:   200,
	}}}
	if got, _ := fire(t, RuleEXFIL001, connectThenRead); got {
		t.Error("RuleEXFIL001 fired when the connection preceded the read (wrong order)")
	}

	readOnly := Input{Evidence: features.Evidence{FirstSeen: map[features.Indicator]uint64{
		features.IndicatorSensitiveRead: 100,
	}}}
	if got, _ := fire(t, RuleEXFIL001, readOnly); got {
		t.Error("RuleEXFIL001 fired with a sensitive read but no outbound connect at all")
	}

	connectOnly := Input{Evidence: features.Evidence{FirstSeen: map[features.Indicator]uint64{
		features.IndicatorOutboundConnect: 100,
	}}}
	if got, _ := fire(t, RuleEXFIL001, connectOnly); got {
		t.Error("RuleEXFIL001 fired with an outbound connect but no sensitive read at all")
	}
}
