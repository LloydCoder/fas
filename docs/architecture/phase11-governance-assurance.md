# FAS Phase 11 — Governance and Assurance

Phase 11 provides machine-readable control assessments and deterministic evidence bundles.

Framework references are versioned strings. Assessments preserve evidence and limitations and use explicit states: NOT_ASSESSED, SUPPORTED, PARTIAL, NOT_SUPPORTED, and UNKNOWN.

SUPPORTED requires traceable evidence. FAS does not convert successful tool execution into a control conclusion.

Evidence bundles contain tenant and analysis identity, deterministic content digests, file sizes, safe relative paths, a versioned schema, metadata, and a manifest digest. The manifest can be independently verified.

Framework mappings are references only. A mapping never implies that FAS or a customer satisfies the referenced framework.
