package features

import (
	"sort"
	"syscall"
)

// Indicator is a category of security-relevant event tracked for the
// earliest time it was observed, so verdict rules can test the order two
// things happened in -- e.g. "was a credential read before or after an
// outbound connection?" (verdict's EXFIL-001).
type Indicator uint8

const (
	IndicatorNone Indicator = iota
	IndicatorSensitiveRead
	IndicatorOutboundConnect
	IndicatorNonRootOutbound
	IndicatorProcessSpawn
	IndicatorPersistenceWrite
	// IndicatorCredentialRead is the narrow counterpart to
	// IndicatorSensitiveRead: it is marked only for a directly reusable
	// secret (see IsCredentialClass), never for a merely sensitive file.
	//
	// The two are kept separate rather than one being narrowed, because
	// they answer different questions. EXFIL-001 needs the narrow one --
	// marking the broad one meant an ordinary install reading its own
	// .npmrc before contacting the registry satisfied a decisive rule
	// (NEW_AUDIT.md NC1). The broad one remains exported as an ML feature,
	// where "read anything sensitive, then connected" is weak evidence
	// rather than a false positive.
	IndicatorCredentialRead
)

// evidenceCap bounds how many distinct raw facts of each unbounded kind
// (comms, endpoints) an EvidenceCollector retains. A session under
// sustained abuse -- or just an unusually chatty install -- must not grow
// this without bound; once a cap is hit, Truncated is set so the verdict
// record honestly reflects that some raw evidence was dropped, without
// losing the classification signal that evidence already produced.
const evidenceCap = 32

// EvidenceCollector accumulates bounded, deduplicated raw evidence -- paths,
// argv shapes, endpoints -- alongside the earliest time each Indicator was
// observed.
//
// It has no mutex of its own and relies entirely on its caller's lock, the
// same pattern DirCounts and TCPAggregator use: internal/session.Session
// mutates it under s.mu and reads it only through Session.Snapshot.
type EvidenceCollector struct {
	paths             map[PathClass]bool
	persistenceWrites map[PathClass]bool
	argv              map[ArgvClass]bool
	comms             map[string]bool
	endpoints         map[string]bool
	nonRootEndpoints  map[string]bool
	firstSeen         map[Indicator]uint64
	truncated         bool
}

// NewEvidenceCollector returns an empty EvidenceCollector.
func NewEvidenceCollector() *EvidenceCollector {
	return &EvidenceCollector{
		paths:             make(map[PathClass]bool),
		persistenceWrites: make(map[PathClass]bool),
		argv:              make(map[ArgvClass]bool),
		comms:             make(map[string]bool),
		endpoints:         make(map[string]bool),
		nonRootEndpoints:  make(map[string]bool),
		firstSeen:         make(map[Indicator]uint64),
	}
}

// persistenceClasses are the PathClasses whose members are startup/scheduled
// -execution locations -- verdict's PERSIST-001 looks for a write into one
// of these, not merely a read of one (a shell innocuously sourcing its own
// ~/.bashrc must not look identical to writing a backdoor into it).
func isPersistenceClass(class PathClass) bool {
	switch class {
	case PathClassShellRC, PathClassCronDir, PathClassSystemdUnit:
		return true
	default:
		return false
	}
}

// isWriteOpen mirrors FiletopAggregator.Add's read/write classification of
// an openat() flags value, for consistency across the codebase: O_RDWR or
// O_WRONLY is an obvious write, and O_CREAT is one too even alongside an
// otherwise read-only access mode, since it means the process is producing
// the file.
func isWriteOpen(flags uint32) bool {
	mode := flags & syscall.O_ACCMODE
	return mode == syscall.O_WRONLY || mode == syscall.O_RDWR || flags&syscall.O_CREAT != 0
}

// AddPath classifies path and, if it matches a known PathClass, records it
// and marks IndicatorSensitiveRead at timestampNs. A credential-class match
// additionally marks IndicatorCredentialRead. If the match is a
// persistence-location class and flags indicates a write, it is also
// recorded as a PersistenceWrite and marks IndicatorPersistenceWrite.
//
// PathClass is a small enum, so the retained sets can never exceed its own
// cardinality -- unlike comms and endpoints, they need no cap of their own.
func (e *EvidenceCollector) AddPath(path string, flags uint32, timestampNs uint64) {
	class := ClassifyPath(path)
	if class == PathClassNone {
		return
	}
	e.paths[class] = true
	e.markFirstSeen(IndicatorSensitiveRead, timestampNs)

	if IsCredentialClass(class) {
		e.markFirstSeen(IndicatorCredentialRead, timestampNs)
	}

	if isPersistenceClass(class) && isWriteOpen(flags) {
		e.persistenceWrites[class] = true
		e.markFirstSeen(IndicatorPersistenceWrite, timestampNs)
	}
}

// AddProcess classifies comm and argv and, if they match a known ArgvClass,
// records it and marks IndicatorProcessSpawn. comm itself is retained
// separately, up to evidenceCap distinct values.
func (e *EvidenceCollector) AddProcess(comm string, argv string, timestampNs uint64) {
	if class := ClassifyArgv(comm, argv); class != ArgvClassNone {
		e.argv[class] = true
	}

	if comm != "" {
		e.addCapped(e.comms, comm)
	}

	e.markFirstSeen(IndicatorProcessSpawn, timestampNs)
}

// AddEndpoint records an "ip:port" endpoint, up to evidenceCap distinct
// values, and marks IndicatorOutboundConnect. When isRoot is false -- the
// connection did not come from the session's npm root PID -- the endpoint
// is also retained (up to its own evidenceCap) as a non-root endpoint and
// IndicatorNonRootOutbound is marked too.
func (e *EvidenceCollector) AddEndpoint(endpoint string, isRoot bool, timestampNs uint64) {
	if endpoint != "" {
		e.addCapped(e.endpoints, endpoint)
	}
	e.markFirstSeen(IndicatorOutboundConnect, timestampNs)

	if isRoot {
		return
	}
	if endpoint != "" {
		e.addCapped(e.nonRootEndpoints, endpoint)
	}
	e.markFirstSeen(IndicatorNonRootOutbound, timestampNs)
}

// addCapped inserts value into set, bounded at evidenceCap distinct entries.
// Once the cap is hit, further distinct values set e.truncated rather than
// growing the set -- values already present are still deduplicated as
// normal, since they cost nothing new.
func (e *EvidenceCollector) addCapped(set map[string]bool, value string) {
	if set[value] {
		return
	}
	if len(set) >= evidenceCap {
		e.truncated = true
		return
	}
	set[value] = true
}

// markFirstSeen records timestampNs for indicator if it is earlier than any
// value already recorded, or if none has been recorded yet. Events can
// arrive out of timestamp order -- five independent ring-buffer readers feed
// one session (AUDIT.md H4) -- so "first" must be a minimum taken across
// every call, not whatever call happens to land first.
func (e *EvidenceCollector) markFirstSeen(indicator Indicator, timestampNs uint64) {
	existing, ok := e.firstSeen[indicator]
	if !ok || timestampNs < existing {
		e.firstSeen[indicator] = timestampNs
	}
}

// Evidence is the immutable, deep-cloned snapshot of an EvidenceCollector at
// one instant. Slice fields are sorted so two snapshots of equal content are
// byte-identical, not merely set-equal.
type Evidence struct {
	Paths             []PathClass
	PersistenceWrites []PathClass
	Argv              []ArgvClass
	Comms             []string
	Endpoints         []string
	NonRootEndpoints  []string
	FirstSeen         map[Indicator]uint64
	Truncated         bool
}

// Snapshot returns a deep-cloned Evidence value. Mutating the collector
// afterwards must not mutate a snapshot a caller is still holding -- the
// same contract session.Session.Snapshot relies on for its other
// aggregators.
func (e *EvidenceCollector) Snapshot() Evidence {
	ev := Evidence{
		FirstSeen: make(map[Indicator]uint64, len(e.firstSeen)),
		Truncated: e.truncated,
	}

	for class := range e.paths {
		ev.Paths = append(ev.Paths, class)
	}
	sort.Slice(ev.Paths, func(i, j int) bool { return ev.Paths[i] < ev.Paths[j] })

	for class := range e.persistenceWrites {
		ev.PersistenceWrites = append(ev.PersistenceWrites, class)
	}
	sort.Slice(ev.PersistenceWrites, func(i, j int) bool { return ev.PersistenceWrites[i] < ev.PersistenceWrites[j] })

	for class := range e.argv {
		ev.Argv = append(ev.Argv, class)
	}
	sort.Slice(ev.Argv, func(i, j int) bool { return ev.Argv[i] < ev.Argv[j] })

	for comm := range e.comms {
		ev.Comms = append(ev.Comms, comm)
	}
	sort.Strings(ev.Comms)

	for ep := range e.endpoints {
		ev.Endpoints = append(ev.Endpoints, ep)
	}
	sort.Strings(ev.Endpoints)

	for ep := range e.nonRootEndpoints {
		ev.NonRootEndpoints = append(ev.NonRootEndpoints, ep)
	}
	sort.Strings(ev.NonRootEndpoints)

	for k, v := range e.firstSeen {
		ev.FirstSeen[k] = v
	}

	return ev
}
