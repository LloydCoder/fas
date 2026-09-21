# Threat Model

FAS treats the full lifecycle as security-sensitive:

```
repository → collection → evidence → graph → investigation → remediation → verification → reporting
```

## Primary trust boundary

The candidate repository and its derived content are **untrusted**.

Source files, configuration, documentation, scanner output, tool metadata, dependency metadata, and model-visible text may contain malicious instructions or data.

## Threat areas

- hostile source and configuration parsing
- prompt injection embedded in analyzed content
- malicious scanner/tool metadata
- unsafe command execution
- dependency and CI supply-chain compromise
- credential exposure
- sandbox escape
- evidence tampering
- cross-analysis data leakage
- confused-deputy behavior
- unauthorized remediation
- resource exhaustion

## Security invariants

1. Untrusted artifacts do not receive ambient production credentials.
2. External tool execution uses bounded execution policy.
3. LLM output cannot create authoritative evidence.
4. Immutable evidence history cannot be rewritten by investigation output.
5. Analysis and snapshot scope must be enforced.
6. Missing evidence is not silently converted into a negative fact.
7. Unsupported execution capabilities fail explicitly.
8. Security-sensitive changes require regression coverage.

## Current runtime boundary

The core product does not execute arbitrary candidate-repository code. Runtime verification remains a controlled extension seam; any future implementation must establish explicit filesystem, network, credential, timeout, process, and resource isolation.

See the phase-specific threat documents in this directory and [SECURITY.md](../../SECURITY.md).