# ADR 0004: Secure and replayable Phase 3 collection

Status: Accepted.

Phase 3 uses deterministic collectors, explicit lifecycle states, a secure subprocess boundary, first-class raw tool artifacts, ToolRun metadata, bounded parsing, scope isolation, and replay manifests. External tools never receive shell interpolation or ambient credentials. Collector output remains observations/evidence; exploitability, findings and verdicts belong to later phases.
