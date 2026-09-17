package features

import "testing"

// TestNGramCounterPush covers the behaviour that survived the move from
// exactly-consecutive to gap-tolerant matching. Every case here passed under
// the old rule too, so a regression shows up as a changed count rather than
// as a test that had to be rewritten to accommodate the new one.
func TestNGramCounterPush(t *testing.T) {
	tests := []struct {
		name     string
		sequence []uint32
		want     PatternCounts
	}{
		{
			name:     "pattern1_only_once_with_nonmatching_tail",
			sequence: []uint32{262, 257, 5, 257, 5, 262},
			want:     PatternCounts{P1: 1},
		},
		{
			name:     "pattern5_process_create",
			sequence: []uint32{57, 59, 61},
			want:     PatternCounts{P5: 1},
		},
		{
			name:     "pattern1_twice_in_a_continuous_stream",
			sequence: []uint32{262, 257, 5, 262, 257, 5},
			want:     PatternCounts{P1: 2},
		},
		{
			name:     "incomplete_pattern_does_not_count",
			sequence: []uint32{99, 98, 97, 96, 95, 262, 257},
			want:     PatternCounts{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter := NewNGramCounter()
			for _, syscallID := range tt.sequence {
				counter.Push(syscallID)
			}

			if got := counter.Snapshot(); got != tt.want {
				t.Fatalf("Snapshot() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestNGramCounterToleratesInterleavedSyscalls is the point of the change.
// A real socket/bind/listen sequence has other calls between its steps, so
// requiring adjacency meant p4 never fired on any captured session.
func TestNGramCounterToleratesInterleavedSyscalls(t *testing.T) {
	counter := NewNGramCounter()

	// socket, fcntl, bind, fcntl, listen -- the shape a real trace has.
	for _, id := range []uint32{41, 72, 49, 72, 50} {
		counter.Push(id)
	}

	if got := counter.Snapshot().P4; got != 1 {
		t.Errorf("P4 = %d, want 1: socket/bind/listen separated by unrelated "+
			"syscalls is still one socket-creation sequence", got)
	}
}

// TestNGramCounterExpiresPartialMatchesBeyondSpan guards the other side of
// the trade-off. Unbounded gaps would make almost any ordered triple occur
// eventually over a stream of hundreds of thousands of syscalls.
func TestNGramCounterExpiresPartialMatchesBeyondSpan(t *testing.T) {
	const filler uint32 = 999

	withinSpan := NewNGramCounter()
	withinSpan.Push(41)
	for i := 0; i < patternSpan-6; i++ {
		withinSpan.Push(filler)
	}
	withinSpan.Push(49)
	withinSpan.Push(50)
	if got := withinSpan.Snapshot().P4; got != 1 {
		t.Errorf("within span: P4 = %d, want 1", got)
	}

	beyondSpan := NewNGramCounter()
	beyondSpan.Push(41)
	for i := 0; i < patternSpan; i++ {
		beyondSpan.Push(filler)
	}
	beyondSpan.Push(49)
	beyondSpan.Push(50)
	if got := beyondSpan.Snapshot().P4; got != 0 {
		t.Errorf("beyond span: P4 = %d, want 0: a socket created and a bind "+
			"%d syscalls later are not one operation", got, patternSpan)
	}
}

// TestNGramCounterCountsNonOverlapping pins that a repeated final element
// does not re-trigger a completed match.
func TestNGramCounterCountsNonOverlapping(t *testing.T) {
	counter := NewNGramCounter()
	for _, id := range []uint32{57, 59, 61, 61, 61} {
		counter.Push(id)
	}

	if got := counter.Snapshot().P5; got != 1 {
		t.Errorf("P5 = %d, want 1: three wait4 calls after one fork/execve is "+
			"one process-creation sequence, not three", got)
	}
}

// TestNGramCounterPatternsAdvanceIndependently verifies that one pattern
// completing cannot consume context another is partway through. p1
// (newfstatat, openat, fstat) and p10 (openat, read, close) share the openat
// at index 1, and both must be able to complete from it.
func TestNGramCounterPatternsAdvanceIndependently(t *testing.T) {
	counter := NewNGramCounter()
	for _, id := range []uint32{262, 257, 5, 0, 3} {
		counter.Push(id)
	}

	got := counter.Snapshot()
	if got.P1 != 1 {
		t.Errorf("P1 = %d, want 1", got.P1)
	}
	if got.P10 != 1 {
		t.Errorf("P10 = %d, want 1: p10's openat/read/close overlaps p1's "+
			"openat and must still be counted", got.P10)
	}
}

// TestNGramCounterEmptyStream verifies a counter that was never pushed to
// reports all zeros rather than panicking.
func TestNGramCounterEmptyStream(t *testing.T) {
	if got := NewNGramCounter().Snapshot(); got != (PatternCounts{}) {
		t.Errorf("Snapshot() on an empty stream = %+v, want all zeros", got)
	}
}
