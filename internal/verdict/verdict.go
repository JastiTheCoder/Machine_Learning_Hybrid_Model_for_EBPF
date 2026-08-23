// Package verdict scores a completed npm-install session against a weighted
// rule set and produces an explainable benign/suspicious/malicious verdict.
//
// This is a userspace pre-screen, not a replacement for the ML model: it
// runs at session completion in the Go daemon (internal/session,
// internal/output), never in eBPF, because forming this opinion needs the
// freedom to loop, correlate and allocate that the kernel side cannot give.
package verdict

import "sort"

// Level is the banded outcome of a session's score against Thresholds.
type Level string

const (
	LevelBenign     Level = "benign"
	LevelSuspicious Level = "suspicious"
	LevelMalicious  Level = "malicious"
)

// Finding is one rule that fired against a session's Input, with enough
// context attached to explain the verdict without re-running the rule.
type Finding struct {
	RuleID    string `json:"rule_id"`
	Weight    int    `json:"weight"`
	Technique string `json:"technique"`
	Evidence  string `json:"evidence"`
}

// Thresholds bands a total score into a Level.
type Thresholds struct {
	Suspicious int `json:"suspicious"`
	Malicious  int `json:"malicious"`
}

// DefaultThresholds are the starting points named in the plan; Stage 8 tunes
// these against the recaptured corpus, and cmd/monitor exposes a flag to
// override them without a rebuild.
var DefaultThresholds = Thresholds{Suspicious: 25, Malicious: 60}

// Verdict is the scored, explainable outcome of evaluating one session's
// Input against a rule set.
type Verdict struct {
	Score      int        `json:"score"`
	Level      Level      `json:"level"`
	Thresholds Thresholds `json:"thresholds"`
	Findings   []Finding  `json:"findings"`
}

// Evaluate scores input against rules and bands the total against
// thresholds. A single Decisive rule firing forces Level to LevelMalicious
// regardless of the total score.
//
// rules and thresholds are explicit parameters rather than package-global
// state, so callers -- and tests -- can evaluate against any rule subset or
// threshold pair without a registry. Stage 3 adds the default registry this
// package ships as its normal rule set.
func Evaluate(input Input, rules []Rule, thresholds Thresholds) Verdict {
	score := 0
	decisive := false
	var findings []Finding

	for _, r := range rules {
		fired, evidence := r.Eval(input)
		if !fired {
			continue
		}

		score += r.Weight
		findings = append(findings, Finding{
			RuleID:    r.ID,
			Weight:    r.Weight,
			Technique: r.Technique,
			Evidence:  evidence,
		})
		if r.Decisive {
			decisive = true
		}
	}

	level := band(score, thresholds)
	if decisive {
		level = LevelMalicious
	}

	// Canonical order -- highest weight first, ID ascending as the
	// tiebreaker -- independent of registration or firing order, so the
	// same Input always reads the same way regardless of how the rule set
	// happened to be assembled.
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Weight != findings[j].Weight {
			return findings[i].Weight > findings[j].Weight
		}
		return findings[i].RuleID < findings[j].RuleID
	})

	return Verdict{
		Score:      score,
		Level:      level,
		Thresholds: thresholds,
		Findings:   findings,
	}
}

func band(score int, t Thresholds) Level {
	switch {
	case score >= t.Malicious:
		return LevelMalicious
	case score >= t.Suspicious:
		return LevelSuspicious
	default:
		return LevelBenign
	}
}
