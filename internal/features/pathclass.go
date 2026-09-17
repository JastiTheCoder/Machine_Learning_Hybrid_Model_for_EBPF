package features

import "strings"

// PathClass identifies why a file path is treated as security-relevant
// evidence.
type PathClass uint8

const (
	PathClassNone PathClass = iota
	PathClassSSHPrivateKey
	PathClassNpmrc
	PathClassAWSCredentials
	PathClassGitConfig
	PathClassEtcPasswd
	PathClassEtcShadow
	PathClassDockerConfig
	PathClassKubeConfig
	PathClassDotEnv
	PathClassCryptoWallet
	PathClassShellRC
	PathClassCronDir
	PathClassSystemdUnit
)

// pathSuffixClasses matches an exact trailing path segment -- the file
// itself is what makes it sensitive, not the directory it happens to live
// in. Suffix matching needs no $HOME resolution, so it works under any
// username the monitored install runs as.
var pathSuffixClasses = []struct {
	suffix string
	class  PathClass
}{
	{"/.ssh/id_rsa", PathClassSSHPrivateKey},
	{"/.ssh/id_dsa", PathClassSSHPrivateKey},
	{"/.ssh/id_ecdsa", PathClassSSHPrivateKey},
	{"/.ssh/id_ed25519", PathClassSSHPrivateKey},
	{"/.npmrc", PathClassNpmrc},
	{"/.aws/credentials", PathClassAWSCredentials},
	{"/.aws/config", PathClassAWSCredentials},
	{"/.gitconfig", PathClassGitConfig},
	{"/etc/passwd", PathClassEtcPasswd},
	{"/etc/shadow", PathClassEtcShadow},
	{"/.docker/config.json", PathClassDockerConfig},
	{"/.kube/config", PathClassKubeConfig},
	{"/.env", PathClassDotEnv},
	{"/.bashrc", PathClassShellRC},
	{"/.zshrc", PathClassShellRC},
	{"/.bash_profile", PathClassShellRC},
	{"/.profile", PathClassShellRC},
	{"/wallet.dat", PathClassCryptoWallet},
	{"/etc/crontab", PathClassCronDir},
}

// pathContainsClasses matches an arbitrary substring for classes whose
// members are identified by directory rather than filename -- a cron.d
// drop-in or a systemd unit can be named anything.
var pathContainsClasses = []struct {
	substr string
	class  PathClass
}{
	{"/cron.d/", PathClassCronDir},
	{"/cron.daily/", PathClassCronDir},
	{"/cron.hourly/", PathClassCronDir},
	{"/systemd/system/", PathClassSystemdUnit},
	{"/.electrum/", PathClassCryptoWallet},
}

// credentialClasses are the PathClasses that identify a secret an attacker
// can directly reuse -- as opposed to a merely sensitive file.
//
// PathClassNpmrc is deliberately excluded. npm reads .npmrc as part of
// ordinary registry-config resolution on every single install, with or
// without a postinstall script: live captures of four unmodified real-world
// packages (lodash, express, chalk, debug -- none of which run any
// install-time script) all read it, so treating it as a credential is a 100%
// false-positive rate with zero discriminative power.
//
// This is the single definition of the set. verdict.RuleCRED001 and
// EvidenceCollector.AddPath both consult it, so narrowing or widening a
// credential rule happens in exactly one place.
var credentialClasses = map[PathClass]bool{
	PathClassSSHPrivateKey:  true,
	PathClassAWSCredentials: true,
	PathClassDockerConfig:   true,
	PathClassKubeConfig:     true,
}

// IsCredentialClass reports whether class identifies a directly reusable
// secret.
func IsCredentialClass(class PathClass) bool {
	return credentialClasses[class]
}

// ClassifyPath reports why path is treated as security-relevant evidence, or
// PathClassNone if it is not.
func ClassifyPath(path string) PathClass {
	for _, m := range pathSuffixClasses {
		if strings.HasSuffix(path, m.suffix) {
			return m.class
		}
	}
	for _, m := range pathContainsClasses {
		if strings.Contains(path, m.substr) {
			return m.class
		}
	}
	return PathClassNone
}
