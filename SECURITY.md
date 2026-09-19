# Security Policy

FAS is security-sensitive software that may process hostile repositories, tool output, security
findings, and verification artifacts.

## Reporting a vulnerability

Please do not report security vulnerabilities in FAS through a public GitHub issue. Use GitHub's
private vulnerability reporting or security advisory mechanism when available. If private
reporting is unavailable, use the security contact configured in the repository settings.

Do not include real credentials, customer information, or unnecessary sensitive data.

## Security scope

Security reports may concern:

- snapshot and cross-analysis isolation
- evidence/provenance integrity
- graph poisoning or path confusion
- collector and parser hardening
- unsafe command or runtime execution
- remediation/verification bypass
- regression-baseline tampering
- permission and identity analysis
- agent/tool/MCP authorization
- prompt injection and LLM boundary violations
- schema validation and unsafe deserialization
- dependency and CI/CD security
- secret leakage

## Phase 5 verification security

Candidate snapshots are untrusted. FAS does not equate a patch, scanner disappearance, or changed
line with remediation. Verification requires explicit before/after snapshot identity, provenance,
bounded graph/path analysis, and evidence-backed security-property evaluation.

Core Phase 5 CI does not execute arbitrary candidate-repository commands and does not expose
production credentials to verification fixtures. The deterministic security-test executor uses
fixture results only. A future runtime backend must provide explicit filesystem, network, secret,
timeout, output, cleanup, and resource isolation.

## LLM boundary

LLMs are advisory investigators. They cannot create authoritative evidence, override deterministic
verification, mutate verification records, or execute arbitrary remediation/runtime commands.

## Coordinated disclosure

Allow reasonable time for investigation and remediation before public disclosure.
