package features

import "testing"

// TestClassifyPath is table-driven across every declared PathClass, each
// with a positive case and a near-miss negative -- a path that resembles
// the sensitive one closely enough that a careless matcher (a bare prefix
// check, or matching on the containing directory alone) would wrongly
// classify it too.
func TestClassifyPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want PathClass
	}{
		{"ssh private key", "/home/x/.ssh/id_rsa", PathClassSSHPrivateKey},
		{"ssh known_hosts is not a private key", "/home/x/.ssh/known_hosts", PathClassNone},

		{"npmrc", "/home/x/.npmrc", PathClassNpmrc},
		{"npmrc backup file is not npmrc", "/home/x/.npmrc.bak", PathClassNone},

		{"aws credentials", "/home/x/.aws/credentials", PathClassAWSCredentials},
		{"aws cli cache is not credentials", "/home/x/.aws/cli/cache/abcd.json", PathClassNone},

		{"global gitconfig", "/home/x/.gitconfig", PathClassGitConfig},
		{"per-repo git config is not the global gitconfig", "/home/x/project/.git/config", PathClassNone},

		{"etc passwd", "/etc/passwd", PathClassEtcPasswd},
		{"etc passwd backup is not passwd", "/etc/passwd-", PathClassNone},

		{"etc shadow", "/etc/shadow", PathClassEtcShadow},
		{"etc shadow backup is not shadow", "/etc/shadow-", PathClassNone},

		{"docker config", "/home/x/.docker/config.json", PathClassDockerConfig},
		{"docker daemon.json is not the client config", "/home/x/.docker/daemon.json", PathClassNone},

		{"kube config", "/home/x/.kube/config", PathClassKubeConfig},
		{"kube cache is not the config", "/home/x/.kube/cache/discovery/foo.json", PathClassNone},

		{"dotenv", "/home/x/project/.env", PathClassDotEnv},
		{"dotenv example is not a real dotenv", "/home/x/project/.env.example", PathClassNone},

		{"wallet.dat", "/home/x/wallet.dat", PathClassCryptoWallet},
		{"wallet.dat backup is not the wallet itself", "/home/x/wallet.dat.bak", PathClassNone},
		{"electrum wallet directory", "/home/x/.electrum/wallets/default_wallet", PathClassCryptoWallet},
		{"file merely named like electrum is not the wallet dir", "/home/x/.electrum-notes.txt", PathClassNone},

		{"bashrc", "/home/x/.bashrc", PathClassShellRC},
		{"bash_history is not an rc file", "/home/x/.bash_history", PathClassNone},

		{"cron.d drop-in", "/etc/cron.d/malicious-job", PathClassCronDir},
		{"crontab file itself", "/etc/crontab", PathClassCronDir},
		{"similarly-named directory is not cron.d", "/etc/cron.d-backup/file", PathClassNone},

		{"systemd system unit", "/etc/systemd/system/evil.service", PathClassSystemdUnit},
		{"systemd network config is not a unit", "/etc/systemd/network/evil.network", PathClassNone},

		{"ordinary dependency file", "/home/x/project/node_modules/lodash/index.js", PathClassNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyPath(tt.path); got != tt.want {
				t.Errorf("ClassifyPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
