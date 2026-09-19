# Phase 3 Collection Threat Model

Assets: source code, dependency metadata, tool output, credentials referenced by configuration, and evidence integrity.

Threats: malicious repositories, path traversal, symlink escape, oversized files, malformed parser input, tool command injection, hostile stdout/stderr, process hangs, secret leakage, cross-snapshot contamination, and provenance spoofing.

Controls: no symlink following; bounded files and output; canonical repository root; argv-only execution; executable allowlist; sanitized environment; timeout/process-group termination; deterministic IDs; analysis/snapshot scope checks; secret-safe normalization; explicit partial/unknown semantics.

Residual risk: kernel/container escape and malicious binaries require an external sandbox boundary and are intentionally outside the Phase 3 in-process trust model.
