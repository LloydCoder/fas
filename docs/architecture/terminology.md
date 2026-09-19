# Canonical FAS Terminology

| Term | Canonical meaning |
|---|---|
| Analysis | Logical security-analysis scope containing snapshots and derived records. |
| Snapshot | Immutable, explicit before/after state identified by repository revision and content lineage. |
| Artifact | Hashable captured input/output object associated with a snapshot. |
| Observation | Raw structured observation produced by a tool or runtime source. |
| Evidence | Provenance-backed observation admissible for security reasoning. |
| Graph Node | Typed, snapshot-bound graph entity with canonical identity. |
| Graph Edge | Typed, directed, provenance-backed relationship between graph nodes. |
| Finding | Security condition supported by evidence. |
| Investigation | Evidence-grounded process that evaluates a finding and reconstructs attack paths. |
| Attack Path | Ordered, evidence-backed route from attacker influence/entry to a security-impacting condition. |
| Verdict | Canonical security conclusion: EXPLOITABLE, NOT_EXPLOITABLE, CONDITIONALLY_EXPLOITABLE, REMEDIATED, REMEDIATION_FAILED, REGRESSED, or UNKNOWN. |
| Remediation | Change intended to remove or mitigate a finding's root cause/security property violation. |
| Verification | Before/after process establishing whether a remediation restored the declared security property. |
| Regression | Reappearance of a previously verified security condition or equivalent dangerous capability. |
| Report | Machine-readable, evidence-traceable representation of an analysis or verification result. |

T0–T5 are provenance/trust classifications, not confidence probabilities. An LLM is an advisor,
not an evidence source of record.
