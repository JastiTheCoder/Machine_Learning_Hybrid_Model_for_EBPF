package verdict

import "testing"

// TestMustRegisterAcceptsUniqueIDs is the non-error half of the registry
// guard: a rule set with distinct IDs builds without panicking and preserves
// every rule.
func TestMustRegisterAcceptsUniqueIDs(t *testing.T) {
	a := Rule{ID: "A", Weight: 1, Eval: func(Input) (bool, string) { return false, "" }}
	b := Rule{ID: "B", Weight: 2, Eval: func(Input) (bool, string) { return false, "" }}

	got := MustRegister(a, b)

	if len(got) != 2 {
		t.Fatalf("MustRegister returned %d rules, want 2", len(got))
	}
}

// TestMustRegisterPanicsOnDuplicateID is the guard itself: two rules sharing
// an ID is a programming error (it would silently double-count that rule's
// weight every time it fires) and must fail loudly at registration time,
// not slip through as an ordinary registry.
func TestMustRegisterPanicsOnDuplicateID(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("MustRegister with a duplicate ID did not panic")
		}
	}()

	dup1 := Rule{ID: "DUP", Weight: 1, Eval: func(Input) (bool, string) { return false, "" }}
	dup2 := Rule{ID: "DUP", Weight: 2, Eval: func(Input) (bool, string) { return false, "" }}

	MustRegister(dup1, dup2)
}

// TestDefaultRulesHasNoDuplicateIDs is a standing assertion over the
// package's own shipped registry, not a synthetic case -- if a future rule
// addition collides with an existing ID, this fails immediately rather than
// waiting to be caught by the fact that MustRegister already panicked at
// package init (which would fail every test in the package, not just this
// one, and less legibly).
func TestDefaultRulesHasNoDuplicateIDs(t *testing.T) {
	seen := make(map[string]bool, len(DefaultRules))
	for _, r := range DefaultRules {
		if seen[r.ID] {
			t.Fatalf("DefaultRules has duplicate ID %q", r.ID)
		}
		seen[r.ID] = true
	}
}
