# Phase 10 integration threats

Required invariants:
1. External webhook payloads are untrusted until authenticated and parsed.
2. Connector destinations are constrained to HTTPS host allowlists.
3. Credentials are never accepted in connector URLs.
4. Duplicate external deliveries cannot create duplicate durable work.
5. Tenant identity is preserved through normalization and job creation.
6. Provider claims are never treated as FAS evidence without an explicit collection step.
7. Connector failures remain explicit and retryable rather than becoming negative security facts.
8. Outbound response sizes and parsing must be bounded by the provider adapter.
