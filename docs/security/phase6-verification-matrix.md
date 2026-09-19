# FAS Phase 6 Security Verification Matrix

This is an internal engineering verification map. It is **not a claim of OWASP ASVS, OWASP Top 10, SLSA, NIST, or other formal compliance**.

OWASP ASVS 5.0.0 is the current stable ASVS release referenced by OWASP. OWASP Top 10:2025 is an awareness document and should not be treated as a complete coverage standard.

## Verification domains

| Domain | FAS control | Evidence in repository | Phase 6 status |
|---|---|---|---|
| Authentication | fail-closed bearer authentication for required API mode | API implementation + security tests | Implemented/bounded |
| Access control | local/non-local binding boundary and service-level resource lookup | API/service implementation | Implemented/bounded |
| Input validation | bounded body, UTF-8, JSON depth/items, ID validation | API/domain/parsers | Implemented |
| Injection | structured argv, no shell construction, executable resolution | secure executor | Implemented/bounded |
| Integrity | SHA-256 objects, snapshot hashes, audit chain | storage/snapshot/audit tests | Implemented |
| Logging | request/job/analysis/audit identifiers and append-oriented audit records | product audit layer | Implemented/bounded |
| Supply chain | immutable GitHub Action SHAs, package build/install checks | CI workflow | Implemented/bounded |
| Secret exposure | sanitized subprocess environment and redacted diagnostics | executor/configuration | Implemented/bounded |
| Exceptional conditions | explicit FAILED/PARTIAL/UNKNOWN/TIMED_OUT/CANCELLED states | collection/investigation/verification contracts | Implemented |
| Prompt injection | repository/tool content treated as data; model output remains advisory | investigation boundary/threat model | Implemented/bounded |
| Resource exhaustion | file, graph, output, worker, request and subprocess limits | product configuration/executor/graph | Implemented/bounded |
| Cross-analysis isolation | analysis/snapshot scope checks | graph/investigation/storage | Implemented/bounded |

## OWASP ASVS 5.0.0 mapping

The Phase 6 implementation primarily exercises ASVS areas concerning validation and business-logic boundaries; authentication and API access; error handling; data protection and integrity; logging and monitoring; secure configuration; file/resource handling; and dependency/software integrity.

This matrix deliberately does not reproduce the ASVS requirement catalog. Individual controls should reference versioned ASVS identifiers when mapped in future work.

## OWASP Top 10:2025 mapping

| OWASP category | FAS relevance |
|---|---|
| A01 Broken Access Control | API authentication, scope isolation, authorization boundaries |
| A02 Security Misconfiguration | configuration validation, non-local binding policy, execution policy |
| A03 Software Supply Chain Failures | pinned CI actions, package/build integrity, dependency checks |
| A04 Cryptographic Failures | SHA-256 content integrity and chained audit hashes |
| A05 Injection | structured subprocess arguments and hostile parser boundaries |
| A06 Insecure Design | evidence-first architecture, explicit UNKNOWN/PARTIAL semantics |
| A07 Authentication Failures | fail-closed bearer authentication |
| A08 Software or Data Integrity Failures | content-addressed artifacts, snapshot identity, audit chain |
| A09 Security Logging & Alerting Failures | structured audit/diagnostic events |
| A10 Mishandling of Exceptional Conditions | bounded errors, timeouts, cancellation, explicit terminal states |

## Agent and prompt-injection controls

FAS treats repository text, scanner output, configuration, and other analyzed material as untrusted data. LLM/investigator output cannot create provenance, mutate immutable evidence, authorize arbitrary execution, or directly override deterministic verdict/verification requirements.

## Remaining bounded capabilities

The current local product does not claim arbitrary candidate-code runtime sandboxing, distributed worker isolation, PostgreSQL/S3 production adapters, universal scanner/vulnerability coverage, or formal OWASP ASVS compliance.
