# FAS Phase 7 — Production Runtime and Scale

Phase 7 adds a production deployment profile without changing evidence-first domain semantics.

| Profile | Database | Objects | Workers | Scope |
|---|---|---|---|---|
| Local | SQLite | local CAS | in-process | single operator |
| Hosted | PostgreSQL | S3-compatible | distributed lease workers | tenant-scoped |

Hosted persistence requires tenant-scoped rows and membership authorization before reads/writes. Roles are reader, analyst, and admin; authorization is deny-by-default.

PostgreSQL job claims use a unique operation key per tenant plus transactionally serialized row access. Worker ownership is lease- and heartbeat-bound; expired leases are recoverable and cancellation is persisted.

S3-compatible storage is content addressed by SHA-256. Writes are conditional, objects are immutable by digest, and reads re-hash content before returning it.

FAS emits dependency-free structured JSON operational events. Production deployments should route them to their logging, metrics, and tracing platform.

TLS termination, secret management, backup policy, HA topology, IAM policy, and network controls remain deployment responsibilities.

## Acceptance criteria

1. PostgreSQL and S3 adapters implement the product persistence/object contracts.
2. Tenant membership and role checks fail closed.
3. Job leasing is safe for multiple workers.
4. Content-addressed objects remain integrity checked.
5. Hosted configuration is explicit and invalid combinations fail closed.
6. Migration and adapter tests pass.
7. CI passes across the supported Python matrix.
8. README, threat model, residual risks, changelog, and architecture docs agree.
