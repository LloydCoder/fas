# Prepare a security-sensitive change

Use this procedure for changes to evidence, verification, execution, authorization, graph semantics, collectors, or security-sensitive CI.

1. Identify the affected trust boundary.
2. Identify the security property that must remain true.
3. Add or update deterministic regression coverage.
4. Preserve provenance and immutable snapshot semantics.
5. Update schemas when public contracts change.
6. Update the threat model or an ADR when the security boundary or rationale changes.
7. Run:

    ruff check .
    pytest --cov=fas --cov-report=term-missing
    pytest tests/security
    python -m pip check
    python scripts/check_schema_parity.py
    python -m build

8. Review the PR for secret leakage and workflow-permission changes.
9. Explain intentional security-semantic changes in the PR.

Never reduce a security gate merely to make CI pass.
