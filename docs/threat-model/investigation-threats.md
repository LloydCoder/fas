# Phase 4 Investigation Threats

| Threat | Mitigation | Test |
|---|---|---|
| Prompt injection | content/data separation | boundary fixtures |
| Tool poisoning | allowlist and structured contracts | unauthorized-tool test |
| Cross-snapshot contamination | case scope validation | scope test |
| Evidence poisoning | immutable provenance | graph validation |
| Graph explosion | bounded traversal | budget tests |
| Model manipulation | model proposals never become evidence | model boundary tests |
