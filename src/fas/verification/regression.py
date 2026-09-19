"""Security baseline and regression detection."""
from __future__ import annotations
from fas.domain import Finding, Snapshot, new_id, VerdictType
from fas.domain.verification import (
    RegressionStatus, SecurityBaseline, SecurityRegression,
)
from fas.graph import GraphEngine, GraphScopeKind


class RegressionEngine:
    def establish_baseline(self, *, finding: Finding, verification_id, security_property: str,
                           snapshot: Snapshot, attack_path_ids=(), evidence_ids=(),
                           graph: GraphEngine, regression_test_ids=()) -> SecurityBaseline:
        controls=tuple(sorted(
            f"{n.canonical_identity}:{n.metadata.get('effective','')}"
            for n in graph.nodes() if n.type.value=="CONTROL"
        ))
        permissions=tuple(sorted(
            f"{n.metadata.get('principal',n.label)}:{n.metadata.get('action','')}:{n.metadata.get('resource','')}"
            for n in graph.nodes() if n.type.value in {"PERMISSION","ROLE","PRINCIPAL"}
        ))
        identities=tuple(sorted(n.canonical_identity for n in graph.nodes() if n.type.value=="IDENTITY"))
        agents=tuple(sorted(
            f"{n.canonical_identity}:{n.metadata.get('capability','')}"
            for n in graph.nodes() if n.type.value=="AGENT"
        ))
        mcp=tuple(sorted(
            f"{n.canonical_identity}:{n.metadata.get('capability','')}:{n.metadata.get('authorization','')}"
            for n in graph.nodes() if n.type.value in {"MCP_SERVER","MCP_TOOL"}
        ))
        return SecurityBaseline(
            id=new_id("security_baseline"),finding_id=finding.id,verification_id=verification_id,
            security_property=security_property,snapshot_id=snapshot.id,
            attack_path_ids=tuple(attack_path_ids),evidence_ids=tuple(evidence_ids),
            control_signatures=controls,permission_signatures=permissions,identity_signatures=identities,
            agent_capability_signatures=agents,mcp_capability_signatures=mcp,
            regression_test_ids=tuple(regression_test_ids),
        )

    def detect(self, *, baseline: SecurityBaseline, current: Snapshot, graph: GraphEngine,
               reachable_baseline_path: bool) -> SecurityRegression:
        if graph.scope.kind != GraphScopeKind.SNAPSHOT or graph.scope.snapshot_id != current.id:
            raise ValueError("regression graph does not match current snapshot")
        dangerous_permissions=[
            n for n in graph.nodes()
            if n.type.value in {"PERMISSION","ROLE","PRINCIPAL"}
            and n.metadata.get("security_property")==baseline.security_property
            and n.metadata.get("effective","true").lower()=="true"
        ]
        if reachable_baseline_path or dangerous_permissions:
            return SecurityRegression(
                id=new_id("security_regression"),verification_id=baseline.verification_id,
                baseline_id=baseline.id,status=RegressionStatus.DETECTED,
                security_property=baseline.security_property,
                evidence_ids=tuple(sorted({e for n in dangerous_permissions for e in n.evidence_ids})),
                attack_path_ids=baseline.attack_path_ids,
                description="Previously verified security property is reachable or a baseline dangerous capability has returned.",
            )
        return SecurityRegression(
            id=new_id("security_regression"),verification_id=baseline.verification_id,
            baseline_id=baseline.id,status=RegressionStatus.NOT_DETECTED,
            security_property=baseline.security_property,
            evidence_ids=(),attack_path_ids=(),
            description="No baseline security condition was detected in the bounded current graph.",
        )
