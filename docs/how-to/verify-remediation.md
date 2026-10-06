# Verify a remediation

Remediation verification is a scoped security-property evaluation, not a generic application-security certificate.

    Original Snapshot
          ↓
    Original Evidence
          ↓
    Remediation
          ↓
    Patched Snapshot
          ↓
    Semantic Graph Diff
          ↓
    Attack-Path Revalidation
          ↓
    Remediation Verdict

Preserve original snapshot identity, record the declared security property, produce the patched snapshot explicitly, compare security-relevant relationships, account for the original path, evaluate residual alternatives where applicable, and treat missing required evidence as UNKNOWN.

Use <code>fas verify --help</code> for supported verification inputs and options.
