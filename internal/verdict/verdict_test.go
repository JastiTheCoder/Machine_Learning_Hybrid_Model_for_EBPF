package verdict

import "testing"

// TestEvaluateNET003DoesNotFireBelowBaseline is the below-threshold half of
// the NET-003 seam: a session whose network syscall share sits under the
// baseline must not be flagged at all.
func TestEvaluateNET003DoesNotFireBelowBaseline(t *testing.T) {
	input := Input{Derived: Derived{NetworkOpsRatio: 0.10}}

	got := Evaluate(input, []Rule{RuleNET003}, DefaultThresholds)

	if got.Score != 0 {
		t.Errorf("Score = %d, want 0", got.Score)
	}
	if got.Level != LevelBenign {
		t.Errorf("Level = %q, want %q", got.Level, LevelBenign)
	}
	if len(got.Findings) != 0 {
		t.Errorf("Findings = %v, want empty", got.Findings)
	}
}

// TestEvaluateNET003FiresAboveBaselineAndNamesFinding is the above-threshold
// half: a session whose network syscall share exceeds the baseline must be
// flagged, scored at the rule's own weight, and named in the resulting
// Finding -- these expected values are hand-worked, not derived by calling
// the rule's own Eval function.
func TestEvaluateNET003FiresAboveBaselineAndNamesFinding(t *testing.T) {
	input := Input{Derived: Derived{NetworkOpsRatio: 0.20}}

	got := Evaluate(input, []Rule{RuleNET003}, DefaultThresholds)

	if got.Score != 10 {
		t.Fatalf("Score = %d, want 10 (RuleNET003.Weight)", got.Score)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("Findings = %v, want exactly one", got.Findings)
	}
	if got.Findings[0].RuleID != "NET-003" {
		t.Errorf("Findings[0].RuleID = %q, want %q", got.Findings[0].RuleID, "NET-003")
	}
	if got.Findings[0].Weight != 10 {
		t.Errorf("Findings[0].Weight = %d, want 10", got.Findings[0].Weight)
	}
	if got.Findings[0].Evidence == "" {
		t.Errorf("Findings[0].Evidence is empty, want a human-readable reason")
	}
}

// TestEvaluateBandsScoreAgainstThresholds exercises the banding boundary in
// isolation from the shipped rule set, using synthetic single-purpose rules
// so the exact threshold arithmetic can be pinned without depending on how
// many real rules happen to sum to a given score.
func TestEvaluateBandsScoreAgainstThresholds(t *testing.T) {
	always := func(weight int, id string) Rule {
		return Rule{
			ID:     id,
			Weight: weight,
			Eval:   func(Input) (bool, string) { return true, "synthetic" },
		}
	}

	thresholds := Thresholds{Suspicious: 25, Malicious: 60}

	tests := []struct {
		name      string
		score     int
		wantLevel Level
	}{
		{"one below suspicious", 24, LevelBenign},
		{"exactly suspicious boundary", 25, LevelSuspicious},
		{"between suspicious and malicious", 59, LevelSuspicious},
		{"exactly malicious boundary", 60, LevelMalicious},
		{"well above malicious", 200, LevelMalicious},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(Input{}, []Rule{always(tt.score, "SYN-001")}, thresholds)
			if got.Score != tt.score {
				t.Fatalf("Score = %d, want %d", got.Score, tt.score)
			}
			if got.Level != tt.wantLevel {
				t.Errorf("Level = %q, want %q (score %d against thresholds %+v)",
					got.Level, tt.wantLevel, tt.score, thresholds)
			}
		})
	}
}

// TestEvaluateDecisiveRuleAloneForcesMaliciousBelowThreshold is the decisive
// half of the two-tier design: a single decisive rule firing must force
// LevelMalicious even though its own weight sits far below the malicious
// threshold and no other rule fired to push the total score up.
func TestEvaluateDecisiveRuleAloneForcesMaliciousBelowThreshold(t *testing.T) {
	decisive := Rule{
		ID:       "SYN-DECISIVE",
		Weight:   5, // well under DefaultThresholds.Malicious (60)
		Decisive: true,
		Eval:     func(Input) (bool, string) { return true, "synthetic decisive" },
	}

	got := Evaluate(Input{}, []Rule{decisive}, DefaultThresholds)

	if got.Score != 5 {
		t.Fatalf("Score = %d, want 5", got.Score)
	}
	if got.Level != LevelMalicious {
		t.Errorf("Level = %q, want %q (decisive rule fired)", got.Level, LevelMalicious)
	}
}

// TestEvaluateNonDecisiveRulesSummingPastThresholdAreMalicious confirms the
// accumulative tier reaches LevelMalicious purely by weight, with no
// decisive rule involved at all.
func TestEvaluateNonDecisiveRulesSummingPastThresholdAreMalicious(t *testing.T) {
	always := func(id string, weight int) Rule {
		return Rule{ID: id, Weight: weight, Eval: func(Input) (bool, string) { return true, "synthetic" }}
	}
	rules := []Rule{always("SYN-A", 30), always("SYN-B", 30)}

	got := Evaluate(Input{}, rules, DefaultThresholds)

	if got.Score != 60 {
		t.Fatalf("Score = %d, want 60", got.Score)
	}
	if got.Level != LevelMalicious {
		t.Errorf("Level = %q, want %q", got.Level, LevelMalicious)
	}
}

// TestEvaluateFindingsOrderedByWeightDescThenIDAsc pins the canonical
// Findings order: highest weight first, ID ascending as the tiebreaker. This
// is independent of the order rules were registered or fired in.
func TestEvaluateFindingsOrderedByWeightDescThenIDAsc(t *testing.T) {
	always := func(id string, weight int) Rule {
		return Rule{ID: id, Weight: weight, Eval: func(Input) (bool, string) { return true, "synthetic" }}
	}
	// Registered out of both weight and ID order on purpose.
	rules := []Rule{
		always("Z-LOW", 10),
		always("A-HIGH", 50),
		always("M-MID", 20),
		always("B-LOW", 10),
	}

	got := Evaluate(Input{}, rules, DefaultThresholds)

	wantOrder := []string{"A-HIGH", "M-MID", "B-LOW", "Z-LOW"}
	if len(got.Findings) != len(wantOrder) {
		t.Fatalf("Findings = %v, want %d entries", got.Findings, len(wantOrder))
	}
	for i, wantID := range wantOrder {
		if got.Findings[i].RuleID != wantID {
			t.Errorf("Findings[%d].RuleID = %q, want %q", i, got.Findings[i].RuleID, wantID)
		}
	}
}

// TestEvaluateFindingsOrderDeterministicAcrossRepeatedCalls guards against a
// map-iteration-order or similar nondeterminism sneaking into Findings: the
// same Input and rule set evaluated twice must produce byte-identical order.
func TestEvaluateFindingsOrderDeterministicAcrossRepeatedCalls(t *testing.T) {
	always := func(id string, weight int) Rule {
		return Rule{ID: id, Weight: weight, Eval: func(Input) (bool, string) { return true, "synthetic" }}
	}
	rules := []Rule{always("R3", 10), always("R1", 10), always("R2", 10)}

	first := Evaluate(Input{}, rules, DefaultThresholds)
	for i := 0; i < 50; i++ {
		again := Evaluate(Input{}, rules, DefaultThresholds)
		if len(again.Findings) != len(first.Findings) {
			t.Fatalf("iteration %d: Findings length changed", i)
		}
		for j := range first.Findings {
			if again.Findings[j].RuleID != first.Findings[j].RuleID {
				t.Fatalf("iteration %d: Findings[%d].RuleID = %q, want %q (first run's order)",
					i, j, again.Findings[j].RuleID, first.Findings[j].RuleID)
			}
		}
	}
}
