# Analyze an authorized repository

FAS treats the target repository as untrusted input.

1. Confirm authorization.
2. Run <code>fas doctor --format json</code>.
3. Run <code>fas tools --format json</code>.
4. Start <code>fas analyze ./path-to-project --format json</code>.
5. Inspect the result with <code>fas status</code>, <code>fas findings</code>, and <code>fas report</code>.

Do not interpret an empty result as proof of security. Review completeness, evidence, provenance, and explicit unknown states.
