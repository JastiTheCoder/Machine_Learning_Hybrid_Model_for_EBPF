package verdict

import "fmt"

// MustRegister builds a rule set, panicking if any two rules share an ID.
//
// A registry with a duplicate ID is a programming error: Evaluate would
// silently double-count that rule's weight every time it fires, and nothing
// about the resulting Verdict would look wrong enough to notice. Failing
// loudly at registration time -- package init, for the rule sets this
// package ships -- catches the mistake at the moment it is made instead of
// leaving it to be discovered later from a miscalibrated score.
func MustRegister(rules ...Rule) []Rule {
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if seen[r.ID] {
			panic(fmt.Sprintf("verdict: duplicate rule ID %q in registry", r.ID))
		}
		seen[r.ID] = true
	}
	return rules
}

// DefaultRules is the rule set this package ships. Registration order here
// does not matter -- Evaluate sorts Findings independently of it.
var DefaultRules = MustRegister(
	RuleEXFIL001,
	RulePERSIST001,
	RuleCRED001,
	RulePROC001,
	RuleNET001,
	RulePROC002,
	RuleDROP001,
	RuleRECON001,
	RuleOBF001,
	RuleNET002,
	RuleNET003,
	RulePROC003,
)
