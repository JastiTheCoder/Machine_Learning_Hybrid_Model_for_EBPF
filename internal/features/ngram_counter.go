// Package features provides higher-level analysis on top of raw eBPF events.
package features

// The ten syscall n-grams, by x86-64 syscall number. Inherited from
// QUT-DV25's pattern set; retained after that dataset's retirement because
// the behaviours they name (a socket being created and connected, a process
// being forked and exec'd) are still the right things to look for, even
// though the dataset that suggested them is gone.
var (
	pattern1FileMetadata  = []uint32{262, 257, 5}  // newfstatat, openat, fstat
	pattern2ReadData      = []uint32{0, 17, 8}     // read, pread64, lseek
	pattern3WriteData     = []uint32{1, 18, 74}    // write, pwrite64, fsync
	pattern4SocketCreate  = []uint32{41, 49, 50}   // socket, bind, listen
	pattern5ProcessCreate = []uint32{57, 59, 61}   // fork, execve, wait4
	pattern6MemoryMap     = []uint32{9, 10, 11}    // mmap, mprotect, munmap
	pattern7FDManage      = []uint32{32, 33, 3}    // dup, dup2, close
	pattern8IPC           = []uint32{22, 1, 0}     // pipe, write, read
	pattern9FileLock      = []uint32{72, 73, 3}    // fcntl, flock, close
	pattern10ErrorHandle  = []uint32{257, 0, 3}    // openat, read, close
)

// patternSpan bounds how many syscalls may elapse between the first and last
// element of a single match.
//
// Matching used to require the three syscalls to be exactly consecutive,
// which made seven of the ten patterns permanently zero across every npm
// session captured. The cause was not that the behaviours never happen --
// a Node install certainly creates sockets and forks processes -- but that
// real kernel traces interleave. A socket/bind/listen sequence has
// setsockopt and fcntl calls between its steps, and other threads' syscalls
// land in the same stream, so the three never appear adjacent. Seven
// always-zero columns carry no information for a model and the eighth, p1,
// fired only because Python's import machinery happens to emit its exact
// triplet (see ml_analysis/QUT_RETIREMENT.md).
//
// Allowing gaps fixes that, but an unbounded gap would be worse than the
// original: over a stream of hundreds of thousands of syscalls, almost any
// ordered triple eventually occurs by chance. The bound keeps a match
// meaning "these happened as part of one operation" rather than "these
// happened at some point during the install". 16 leaves room for the
// handful of calls that realistically interleave within one logical
// operation while staying far short of install-wide coincidence.
const patternSpan = 16

// PatternCounts stores counts for the syscall n-gram patterns.
//
// Values are not comparable across schema versions: before 1.2.0 these
// counted exactly-consecutive triplets, and from 1.2.0 they count
// gap-tolerant ones. Sessions captured under the two rules must not be
// pooled into one training set on these columns.
type PatternCounts struct {
	P1  int `json:"p1_file_metadata"`
	P2  int `json:"p2_read_data"`
	P3  int `json:"p3_write_data"`
	P4  int `json:"p4_socket_create"`
	P5  int `json:"p5_process_create"`
	P6  int `json:"p6_memory_map"`
	P7  int `json:"p7_fd_manage"`
	P8  int `json:"p8_ipc"`
	P9  int `json:"p9_file_lock"`
	P10 int `json:"p10_error_handle"`
}

// patternMatcher tracks how much of one pattern has been seen so far.
//
// Each pattern advances independently, so a match of one cannot consume the
// context another is partway through -- which is why there is no longer a
// window shared between them.
type patternMatcher struct {
	pattern []uint32
	cursor  int
	startAt uint64
}

// push advances the matcher by one syscall and reports whether that syscall
// completed a match.
//
// Occurrences are counted non-overlapping: the cursor resets on completion,
// so the stream A B C C C yields one match of {A,B,C} rather than three.
//
// A syscall that fails to advance a partial match is ignored rather than
// treated as a possible fresh start, so A B A B C counts one match, not two
// attempts. This can undercount when a pattern's own elements repeat, but it
// can never overcount, which is the safer direction for a feature feeding a
// detector.
func (m *patternMatcher) push(syscallID uint32, pos uint64) bool {
	if len(m.pattern) == 0 {
		return false
	}

	// Abandon a partial match whose first element is now too far behind.
	if m.cursor > 0 && pos-m.startAt >= patternSpan {
		m.cursor = 0
	}

	if syscallID != m.pattern[m.cursor] {
		return false
	}

	if m.cursor == 0 {
		m.startAt = pos
	}
	m.cursor++

	if m.cursor == len(m.pattern) {
		m.cursor = 0
		return true
	}
	return false
}

// NGramCounter tracks pattern match counts over a syscall stream.
type NGramCounter struct {
	matchers [10]patternMatcher
	counts   PatternCounts
	pos      uint64
}

// NewNGramCounter creates an initialized NGramCounter.
func NewNGramCounter() *NGramCounter {
	return &NGramCounter{
		matchers: [10]patternMatcher{
			{pattern: pattern1FileMetadata},
			{pattern: pattern2ReadData},
			{pattern: pattern3WriteData},
			{pattern: pattern4SocketCreate},
			{pattern: pattern5ProcessCreate},
			{pattern: pattern6MemoryMap},
			{pattern: pattern7FDManage},
			{pattern: pattern8IPC},
			{pattern: pattern9FileLock},
			{pattern: pattern10ErrorHandle},
		},
	}
}

// Push feeds one syscall to every pattern matcher and updates the counts.
func (c *NGramCounter) Push(syscallID uint32) {
	pos := c.pos
	c.pos++

	targets := [10]*int{
		&c.counts.P1, &c.counts.P2, &c.counts.P3, &c.counts.P4, &c.counts.P5,
		&c.counts.P6, &c.counts.P7, &c.counts.P8, &c.counts.P9, &c.counts.P10,
	}

	for i := range c.matchers {
		if c.matchers[i].push(syscallID, pos) {
			*targets[i]++
		}
	}
}

// Snapshot returns a copy of the current pattern counts.
func (c *NGramCounter) Snapshot() PatternCounts {
	return c.counts
}
