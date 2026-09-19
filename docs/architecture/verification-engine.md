# Phase 5 — Verification Engine

Phase 5 verifies a remediation against explicit before/after snapshots. It extends Phase 4 graph
and attack-path primitives; it does not create a second reasoning engine.

## Pipeline

```
Finding → Investigation evidence → Remediation → Candidate snapshot
       → Candidate evidence/graph → Semantic graph diff
       → Original-path revalidation → Residual/alternate-path search
       → Security tests → Regression baseline → Verification result
```

## Deterministic precedence

The verifier treats graph reachability, evidence provenance, snapshot integrity, permission
differentials, and controlled security-test results as authoritative over model assertions.

A scanner becoming quiet or a source line changing is never sufficient by itself.

## Result policy

- persistent original or equivalent alternate path → `REMEDIATION_FAILED`
- verified elimination of the security property with complete candidate evidence → `REMEDIATED`
- previously verified property returning against a baseline → `REGRESSED`
- insufficient/incomplete evidence → `UNKNOWN`

The security-property outcome is separately recorded as ELIMINATED, MITIGATED,
PARTIALLY_MITIGATED, UNCHANGED, WORSENED, or UNKNOWN.

## Snapshot isolation

Original and candidate snapshots must be distinct and graph scope must match them exactly.
Historical evidence is never mutated. Candidate absence is only treated as negative evidence
when the candidate graph is complete.

## Semantic graph diff

Nodes and edges are compared by canonical semantic identity rather than serialized IDs. The
diff additionally classifies permission, identity, trust-boundary, endpoint, agent/tool,
credential, data-flow, control, and dependency changes.

## Runtime tests

Core CI uses a deterministic fixture executor. There is deliberately no arbitrary shell executor
in Phase 5. A future runtime backend must implement explicit sandbox, filesystem, network, secret,
timeout, and resource policies before candidate code can be executed.

## Scope

Verification is scoped to the finding's security property, affected components, related paths,
controls, identities, permissions, agent/MCP capabilities, and configured regression checks.
It does not claim that the entire target application is secure.
