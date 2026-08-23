package features

import (
	"path/filepath"
	"strings"
)

// ArgvClass identifies why a spawned process's command line is treated as
// security-relevant evidence.
type ArgvClass uint8

const (
	ArgvClassNone ArgvClass = iota
	ArgvClassShellSpawn
	ArgvClassNetworkTool
	ArgvClassBase64Decode
	ArgvClassEvalExec
	ArgvClassChmodExec
)

var shellNames = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true}

var networkToolNames = map[string]bool{"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true}

// ClassifyArgv reports why comm and its decoded argv string are treated as
// security-relevant evidence, or ArgvClassNone if they are not.
//
// Matching is token-based, not a raw substring search over argv: "curl"
// only fires when it is comm or argv's own binary name (its own argv[0]),
// never as an incidental substring of some other word (e.g. "curly").
func ClassifyArgv(comm string, argv string) ArgvClass {
	fields := strings.Fields(argv)
	argv0 := comm
	if len(fields) > 0 {
		argv0 = filepath.Base(fields[0])
	}
	comm0 := filepath.Base(comm)

	switch {
	case shellNames[comm0] || shellNames[argv0]:
		return ArgvClassShellSpawn
	case networkToolNames[comm0] || networkToolNames[argv0]:
		return ArgvClassNetworkTool
	case argv0 == "base64" && (hasField(fields, "-d") || hasField(fields, "--decode")):
		return ArgvClassBase64Decode
	case argv0 == "node" && hasField(fields, "-e"):
		return ArgvClassEvalExec
	case strings.Contains(argv, "eval("):
		return ArgvClassEvalExec
	case argv0 == "chmod" && (hasField(fields, "+x") || hasField(fields, "755") || hasField(fields, "777")):
		return ArgvClassChmodExec
	default:
		return ArgvClassNone
	}
}

func hasField(fields []string, target string) bool {
	for _, f := range fields {
		if f == target {
			return true
		}
	}
	return false
}
