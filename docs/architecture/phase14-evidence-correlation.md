# Phase 14 — Evidence Correlation and Temporal Indexing

Phase 14 adds deterministic correlation primitives over existing Evidence records.

Correlation is advisory data organization, not a security conclusion. FAS never deletes,
merges, rewrites, or downgrades evidence because two records share a fingerprint.

The module provides:
- stable fingerprints from canonical evidence attributes;
- deterministic correlation groups;
- timezone-aware temporal filtering;
- explicit ordering by observed timestamp and evidence identifier.

It does not create findings or verdicts, infer exploitability, or alter provenance.
