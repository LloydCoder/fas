# ADR 0007 — Attack-Path Revalidation

## Status

Accepted.

Phase 5 reuses Phase 4 graph traversal and bounded path enumeration. The original attack path is
retained as an immutable reference. Candidate analysis searches for the original semantic
source/sink region and bounded alternate routes. Scanner disappearance is not a verification
criterion.
