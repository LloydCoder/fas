# Evidence Model

FAS separates observations, evidence, findings, investigation conclusions, remediation metadata,
and verification evidence.

## Provenance

T0–T5 classify how an observation was established:

- T0 assertion
- T1 LLM inference
- T2 tool observation
- T3 deterministic artifact verification
- T4 reproduced runtime observation
- T5 independently reproduced security test

These are provenance/trust classifications, not probabilities of truth.

## Phase 5

[Verification evidence](verification-evidence.md) is append-only and snapshot-bound. A verification
claim must reference traceable evidence, an artifact, graph diff, attack-path comparison, or
controlled test result. Missing evidence is explicit and never converted into a successful
remediation conclusion.
