# Run local diagnostics

Use diagnostics before investigating a failing analysis or opening a support issue.

    fas doctor --format json
    fas tools --format json

Check runtime availability, configured storage, available external tools, security-relevant diagnostics, and redaction behavior.

Do not paste secrets or sensitive repository content into public issues.

For reproducibility, include FAS version, Python version, operating system, command, and sanitized diagnostic output.
