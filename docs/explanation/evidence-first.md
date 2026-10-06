# Evidence-first security analysis

FAS separates:

    Observation → Evidence → Finding → Attack Path → Verdict

An observation is something a collector or adapter reported. Evidence records how that observation was established and preserved. A finding is an interpreted security condition. An attack path connects security-relevant relationships. A verdict states a conclusion within the available evidence.

If required evidence is missing or contradictory, FAS can return UNKNOWN. This is deliberate: absence of evidence is not evidence of absence.

Remediation conclusions should account for before/after snapshots, semantic relationship changes, the original path, and residual alternatives where applicable.
