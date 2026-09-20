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
fixture results only. The Linux sandbox backend uses bubblewrap when available and fails closed when the requested isolation backend is unavailable. It isolates the target repository, process/user/PID/IPC/UTS/network namespaces as configured, removes ambient credential files, applies resource limits, and restricts the visible filesystem. Other operating systems and runtime backends remain bounded/unsupported unless explicitly implemented.

## LLM boundary

LLMs are advisory investigators. They cannot create authoritative evidence, override deterministic
verification, mutate verification records, or execute arbitrary remediation/runtime commands.

## Coordinated disclosure

Allow reasonable time for investigation and remediation before public disclosure.


## Phase 6 product boundary

The default HTTP API binds to 127.0.0.1 and has authentication disabled only for local development.
Any externally reachable deployment must enable bearer-token authentication. The API rejects oversized
JSON bodies and does not expose arbitrary filesystem or shell execution.

The local SQLite backend is suitable for local operation and deterministic CI, not as a claim of
horizontally scaled production storage. Deployments requiring PostgreSQL, S3-compatible storage, or
runtime code execution must supply dedicated hardened adapters.

Secrets are redacted from product diagnostics where recognized. Source content is not sent to external
AI services by the core product layer. Network use is not required for core local analysis.
