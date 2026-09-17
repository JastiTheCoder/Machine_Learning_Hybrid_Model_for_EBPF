package features

// SensitiveAccess is the ML-facing projection of the security-relevant facts
// an EvidenceCollector already gathers.
//
// Until now those facts reached only the verdict engine. The exported feature
// vector was capped at the 36 columns QUT-DV25 defines, which is why
// dir_counter.go folds .ssh/.aws reads into other_dir_access -- and why a
// capture of a package whose sole behaviour is reading ~/.ssh/id_rsa produced
// a feature vector containing no indication that any key was read. QUT-DV25
// has since been retired as a training source (ml_analysis/QUT_RETIREMENT.md),
// so the schema no longer has to match it and this signal can be surfaced.
//
// Fields are 0/1 presence flags rather than counts because EvidenceCollector
// deduplicates by PathClass: reading one SSH key and reading five are equally
// damning, and the distinction is not recorded upstream anyway.
type SensitiveAccess struct {
	// Directly reusable secrets.
	SSHPrivateKeyRead  int `json:"ssh_private_key_read"`
	AWSCredentialsRead int `json:"aws_credentials_read"`
	DockerConfigRead   int `json:"docker_config_read"`
	KubeConfigRead     int `json:"kube_config_read"`
	CryptoWalletRead   int `json:"crypto_wallet_read"`

	// Sensitive but not directly reusable.
	DotEnvRead    int `json:"dotenv_read"`
	NpmrcRead     int `json:"npmrc_read"`
	GitConfigRead int `json:"gitconfig_read"`

	// Host reconnaissance.
	EtcPasswdRead int `json:"etc_passwd_read"`
	EtcShadowRead int `json:"etc_shadow_read"`

	// Persistence locations, read and written separately: a shell sourcing
	// its own ~/.bashrc must not look identical to a backdoor being written
	// into it.
	ShellRCRead       int `json:"shellrc_read"`
	CronDirRead       int `json:"crondir_read"`
	SystemdUnitRead   int `json:"systemd_unit_read"`
	PersistenceWrites int `json:"persistence_writes"`

	// Aggregates.
	CredentialClassRead int `json:"credential_class_read"`
	DistinctEndpoints   int `json:"distinct_endpoints"`
	NonRootEndpoints    int `json:"non_root_endpoints"`

	// Ordering. Aggregate counts cannot express these: read-then-send and
	// send-then-read produce identical totals, and only the first is
	// exfiltration. This is the signal EXFIL-001 keys on, made available to
	// a model rather than only to the rule engine.
	CredentialReadBeforeConnect int `json:"credential_read_before_connect"`
	SensitiveReadBeforeConnect  int `json:"sensitive_read_before_connect"`
	SpawnBeforeConnect          int `json:"spawn_before_connect"`
}

// BuildSensitiveAccess projects an Evidence snapshot into the feature struct.
func BuildSensitiveAccess(ev Evidence) SensitiveAccess {
	present := make(map[PathClass]bool, len(ev.Paths))
	for _, class := range ev.Paths {
		present[class] = true
	}

	credential := false
	for _, class := range ev.Paths {
		if IsCredentialClass(class) {
			credential = true
			break
		}
	}

	return SensitiveAccess{
		SSHPrivateKeyRead:  boolToInt(present[PathClassSSHPrivateKey]),
		AWSCredentialsRead: boolToInt(present[PathClassAWSCredentials]),
		DockerConfigRead:   boolToInt(present[PathClassDockerConfig]),
		KubeConfigRead:     boolToInt(present[PathClassKubeConfig]),
		CryptoWalletRead:   boolToInt(present[PathClassCryptoWallet]),

		DotEnvRead:    boolToInt(present[PathClassDotEnv]),
		NpmrcRead:     boolToInt(present[PathClassNpmrc]),
		GitConfigRead: boolToInt(present[PathClassGitConfig]),

		EtcPasswdRead: boolToInt(present[PathClassEtcPasswd]),
		EtcShadowRead: boolToInt(present[PathClassEtcShadow]),

		ShellRCRead:       boolToInt(present[PathClassShellRC]),
		CronDirRead:       boolToInt(present[PathClassCronDir]),
		SystemdUnitRead:   boolToInt(present[PathClassSystemdUnit]),
		PersistenceWrites: len(ev.PersistenceWrites),

		CredentialClassRead: boolToInt(credential),
		DistinctEndpoints:   len(ev.Endpoints),
		NonRootEndpoints:    len(ev.NonRootEndpoints),

		CredentialReadBeforeConnect: boolToInt(
			precedes(ev, IndicatorCredentialRead, IndicatorOutboundConnect)),
		SensitiveReadBeforeConnect: boolToInt(
			precedes(ev, IndicatorSensitiveRead, IndicatorOutboundConnect)),
		SpawnBeforeConnect: boolToInt(
			precedes(ev, IndicatorProcessSpawn, IndicatorOutboundConnect)),
	}
}

// precedes reports whether both indicators were observed and first fired
// strictly before second. Equal timestamps are not a precedence: five
// independent ring-buffer readers feed one session, so two events sharing a
// timestamp carry no reliable ordering.
func precedes(ev Evidence, first, second Indicator) bool {
	firstAt, firstOK := ev.FirstSeen[first]
	secondAt, secondOK := ev.FirstSeen[second]
	if !firstOK || !secondOK {
		return false
	}
	return firstAt < secondAt
}

// SensitiveAccessColumns returns the CSV column names in the same order as
// Values. Keeping the two adjacent is deliberate: the pre-existing 39-column
// export splits its header (cmd/dataset/exporter) from its row
// (output.SessionRecord.ToCSVRow) across two packages, where they can drift
// silently.
func SensitiveAccessColumns() []string {
	return []string{
		"ssh_private_key_read",
		"aws_credentials_read",
		"docker_config_read",
		"kube_config_read",
		"crypto_wallet_read",
		"dotenv_read",
		"npmrc_read",
		"gitconfig_read",
		"etc_passwd_read",
		"etc_shadow_read",
		"shellrc_read",
		"crondir_read",
		"systemd_unit_read",
		"persistence_writes",
		"credential_class_read",
		"distinct_endpoints",
		"non_root_endpoints",
		"credential_read_before_connect",
		"sensitive_read_before_connect",
		"spawn_before_connect",
	}
}

// Values returns the field values in the same order as
// SensitiveAccessColumns.
func (s SensitiveAccess) Values() []int {
	return []int{
		s.SSHPrivateKeyRead,
		s.AWSCredentialsRead,
		s.DockerConfigRead,
		s.KubeConfigRead,
		s.CryptoWalletRead,
		s.DotEnvRead,
		s.NpmrcRead,
		s.GitConfigRead,
		s.EtcPasswdRead,
		s.EtcShadowRead,
		s.ShellRCRead,
		s.CronDirRead,
		s.SystemdUnitRead,
		s.PersistenceWrites,
		s.CredentialClassRead,
		s.DistinctEndpoints,
		s.NonRootEndpoints,
		s.CredentialReadBeforeConnect,
		s.SensitiveReadBeforeConnect,
		s.SpawnBeforeConnect,
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
