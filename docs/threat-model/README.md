# FAS Threat Model

FAS analyzes potentially hostile software and security artifacts. Analysis inputs must therefore be treated as untrusted.

## Initial threat areas

- malicious repositories
- hostile source code
- prompt injection embedded in analyzed content
- malicious tool metadata
- unsafe command execution
- dependency compromise
- credential exposure
- sandbox escape
- evidence tampering
- cross-analysis data leakage
- confused-deputy behavior
- unauthorized remediation

## Security boundary

The analysis execution environment must be treated as a sandbox boundary. Untrusted artifacts must not receive ambient access to production credentials, internal networks, or privileged host resources.

This document will be expanded with assets, trust boundaries, threats, mitigations, and verification requirements as implementation matures.
