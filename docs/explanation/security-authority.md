# Security authority model

FAS uses explicit authority boundaries.

| Component | Authority |
|---|---|
| Collectors | Produce observations |
| Evidence layer | Preserve provenance and integrity |
| Graph | Represent evidence-backed relationships |
| Analysis | Correlate and reason over evidence |
| Verdict engine | Produce formal conclusions |
| LLM | Advisory only |
| Reporting | Present established conclusions |
| Remediation verification | Evaluate declared properties against explicit snapshots |

A component must not silently grant itself authority owned by another layer.
