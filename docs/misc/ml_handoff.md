# ML Handoff — moved

The canonical document is [`docs/ml_handoff.md`](../ml_handoff.md).

This file was a verbatim copy (NEW_AUDIT.md, Medium: "`docs/ml_handoff.md` is
duplicated verbatim"; see also
[`planned-fixes/cleanup-tasks/02-duplicate-ml-handoff-doc.md`](../planned-fixes/cleanup-tasks/02-duplicate-ml-handoff-doc.md)).
It is replaced by this pointer rather than left in place, because the schema
1.2.0 export changes — 59 columns instead of 39, and a changed counting rule for
`p1`-`p10` — were applied to the canonical copy only. Two documents describing
the same CSV differently is worse than one, and a stale copy that still says
"expected: 39" would send someone debugging a column count that is correct.

The duplicate is still recorded as open in the audit because the references to
this path elsewhere in `docs/` have not been repointed yet.
