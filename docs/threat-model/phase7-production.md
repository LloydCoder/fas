# Phase 7 production threats

New trust boundaries are tenant membership and authorization, PostgreSQL, S3 object storage, distributed worker leases, and production telemetry.

Required invariants:
1. Every hosted persistence operation is tenant-scoped.
2. Missing membership fails closed.
3. Role elevation is never inferred from request metadata.
4. Worker ownership is lease-bound and expires.
5. Retrieved objects are verified by digest.
6. Storage credentials never enter evidence payloads.
7. Operational logs do not contain bearer tokens or raw analyzed source.
8. Audit-chain semantics remain append-only.
9. SQLite mode cannot be represented as HA.
10. Production adapters do not weaken deterministic evidence or verdict boundaries.
