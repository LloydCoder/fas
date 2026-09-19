# ADR 0011 — Remediation Evidence Immutability

## Status

Accepted.

Original collection evidence, remediation metadata, and verification evidence are separate
append-only records. Verification references prior evidence but never rewrites it. This preserves
forensic reconstruction of the before and after states.
