# ADR 0010 — Controlled Runtime Verification

## Status

Accepted.

Phase 5 provides a runtime-test protocol and deterministic fixture executor, but no arbitrary
shell/process execution backend. Candidate repositories are untrusted. Any future executor must
enforce explicit target, network, filesystem, secret, timeout, output, cleanup, and resource
policies.
