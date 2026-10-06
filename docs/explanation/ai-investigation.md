# AI-assisted investigation

FAS treats model output as advisory.

The intended loop is:

    Hypothesis
       ↓
    Evidence Request
       ↓
    Deterministic Collection
       ↓
    Verified Evidence
       ↓
    Evidence Graph Update
       ↓
    Reassessment

Models may help formulate hypotheses, prioritize evidence requests, or summarize established evidence.

They must not create authoritative evidence, mutate immutable evidence history, override deterministic verification, authorize arbitrary commands or remediation, or obtain unrestricted filesystem, database, secret, or network access.
