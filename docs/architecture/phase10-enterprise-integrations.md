# FAS Phase 10 — Enterprise Integrations and Distributed Security Intelligence

Phase 10 establishes the integration substrate used by enterprise deployments.

## Integration model

External systems produce integration events. FAS authenticates and bounds the transport, normalizes the event, applies tenant-scoped idempotency, and only then allows an application workflow to request evidence collection or analysis.

External payloads remain untrusted input. They are not evidence merely because they came from a trusted vendor.

## Current connector boundary

The first production connector is GitHub REST access through an HTTPS host allowlist. Webhook payloads support GitHub HMAC verification and bounded JSON normalization.

The connector layer is deliberately provider-neutral so GitLab, Jira, Linear, SIEM, SOAR, cloud, registry, and observability adapters can share the same transport, authentication, cursor, retry, and tenant-isolation contracts.

## Distributed model

The Phase 7 PostgreSQL job lease is the execution primitive. Phase 10 integration events can therefore be converted into idempotent durable jobs without introducing a second queue authority.

Event fingerprints are deterministic and tenant-scoped. Duplicate deliveries must be acknowledged without creating duplicate work.

## Security invariants

- HTTPS only for outbound connectors.
- Configured host allowlist; no arbitrary URL fetching.
- No credentials embedded in URLs.
- Webhook bodies are size bounded.
- Webhook signatures are verified before application processing.
- External payloads cannot create authoritative evidence or verdicts.
- Tenant scope is preserved from ingestion through durable work.
