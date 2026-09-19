# Architecture

FAS is a modular monolith with explicit security-analysis boundaries.

## Lifecycle

```
API / CLI
  ↓
Application / collection orchestration
  ↓
Collectors / adapters
  ↓
Evidence + provenance
  ↓
Evidence Graph
  ↓
Investigation
  ↓
Exploitability / verdict proposal
  ↓
Remediation
  ↓
Verification
  ↓
Reporting
```

Phase 5 is implemented by [verification-engine.md](verification-engine.md).

## Phase boundaries

1. Foundations — domain contracts and immutable snapshots.
2. Evidence Graph — provenance-aware graph storage and bounded queries.
3. Security Collection — hostile-input-safe collectors and adapters.
4. Investigation — evidence-grounded deterministic investigation plus constrained LLM advisory boundary.
5. Verification — deterministic before/after remediation verification, semantic graph diff, attack-path revalidation, regression baselines, and controlled security-test contracts.
6. Productization — future API/worker/reporting/distribution expansion.

The repository does not claim that Phase 6 productization is implemented.
