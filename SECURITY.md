# Security Policy

FAS is security-sensitive software that may process hostile repositories, source code, configuration, scanner output, and security evidence.

## Reporting a vulnerability

**Do not report security vulnerabilities through a public GitHub issue.**

Use GitHub's private vulnerability reporting/security advisory mechanism for this repository when available.

If private reporting is unavailable, contact the maintainer privately through GitHub: **@LloydCoder**.

Do not include real credentials, customer information, private source code, or unnecessary sensitive data.

## Response targets

These are operational targets, not guarantees:

| Stage | Target |
|---|---|
| Initial acknowledgement | Within 2 business days |
| Initial triage | Within 5 business days |
| Severity assessment | Within 7 business days |
| Remediation/disclosure plan | Coordinated according to severity and affected versions |

Complex reports, upstream dependencies, or coordinated-disclosure constraints may require more time.

## Scope

Reports may concern snapshot isolation, evidence/provenance integrity, graph poisoning, parser hardening, unsafe execution, verification bypass, baseline tampering, permission analysis, agent/tool/MCP authorization, prompt injection, unsafe deserialization, dependency/CI security, secret leakage, API authentication/authorization, or denial of service.

## Security boundaries

Candidate repositories and external tool output are untrusted. FAS must not treat a scanner disappearance, changed line, successful build, or model-generated explanation as proof of remediation by itself.

Verification requires explicit before/after snapshot identity, provenance, bounded graph/path analysis, and evidence-backed evaluation of the declared security property.

LLMs are advisory and cannot create authoritative evidence, mutate immutable evidence history, bypass deterministic verification, or authorize arbitrary remediation/runtime commands.

## Runtime security

The default HTTP API binds to 127.0.0.1. Authentication may be disabled for local development only. Any externally reachable deployment must enable bearer-token authentication.

The local SQLite backend is intended for local operation and deterministic CI; it is not by itself a claim of horizontally scaled production storage.

## Supply-chain security

The repository uses locked dependencies and automated security checks including dependency review, dependency auditing, secret scanning, CodeQL, SBOM generation, and artifact attestations.

Security-sensitive workflow changes must preserve least-privilege permissions and immutable action pinning.

## Coordinated disclosure

Please allow reasonable time for investigation, remediation, affected-version assessment, and coordination before public disclosure.
