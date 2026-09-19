# ADR 0005 — Snapshot-to-Snapshot Verification

## Status

Accepted.

## Decision

Phase 5 compares two explicit immutable snapshots. The original snapshot remains historical
evidence; candidate evidence is appended as new evidence. A verification cannot mix graph,
artifact, or evidence records across snapshot boundaries.

## Consequences

This makes verification reproducible and prevents a patched artifact from silently rewriting
the evidence that established the original finding. Complete candidate graphs are required for
negative reachability conclusions.
