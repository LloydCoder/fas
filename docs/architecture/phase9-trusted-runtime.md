# FAS Phase 9 — Trusted Runtime Verification

Phase 9 introduces a controlled runtime adapter for security-test definitions.

The adapter:
- delegates execution to SecureExecutor
- requires explicit executable allowlisting
- requires the sandbox execution mode
- denies network access
- denies secrets
- inherits bounded timeout/output/resource controls
- records an output digest and explicit runtime status

Bubblewrap is treated as a policy-construction primitive, not as the security model itself. FAS owns the namespace, filesystem, network, environment, resource and executable restrictions it passes to the backend.

The adapter refuses unsupported network or secret policies instead of silently broadening execution.

Runtime results remain verification evidence inputs; they do not bypass the existing snapshot, provenance, remediation, or verdict rules.
