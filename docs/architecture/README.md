# FAS Architecture

FAS is initially designed as a modular monolith with isolated execution workers.

## Logical flow

```
API / CLI
  -> Analysis Orchestrator
  -> Discovery and Collectors
  -> Evidence Normalization
  -> Evidence Graph
  -> Security Analysis
  -> Exploitability Analysis
  -> Verdict
  -> Remediation Verification
```

## Architectural rule

Every material security conclusion must be traceable to evidence and to the immutable snapshot in which that evidence was observed.

Detailed architecture decision records belong in [../decisions/](../decisions/).
