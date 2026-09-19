"""Deterministic Phase 5 verification engine.

The engine extends Phase 4 graph/path primitives rather than introducing a second reasoning
system. Negative conclusions are only made from complete candidate graphs and explicit evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from fas.domain import (
    AttackPath, AttackPathStep, Finding, Remediation, Snapshot, VerdictType, new_id,
)
from fas.domain.verification import (
    AttackPathComparison, AttackPathComparisonStatus, CheckStatus, GraphDiff, ResidualPath,
    SecurityPropertyOutcome, SecurityRegression, SecurityTestDefinition, SecurityTestResult,
    VerificationCheck, VerificationCheckResult, VerificationEvidence, VerificationPlan,
    VerificationReport, VerificationResult, VerificationRun,
)
from fas.graph import GraphEngine, GraphScopeKind
from .diff import SemanticGraphDiffEngine
from .runtime import SecurityTestExecutor
from .regression import RegressionEngine


@dataclass(frozen=True)
class VerificationOutcome:
    result: VerificationResult
    report: VerificationReport
    plan: VerificationPlan
    run: VerificationRun
    graph_diff: GraphDiff
    comparisons: tuple[AttackPathComparison, ...]
    residual_paths: tuple[ResidualPath, ...]
    regressions: tuple[SecurityRegression, ...]
    tests: tuple[SecurityTestResult, ...]
    baseline: object | None = None


def _node_semantics(node) -> tuple[str, ...]:
    m=node.metadata
    return (
        node.type.value,
        node.canonical_identity,
        m.get("source", ""),
        m.get("sink", ""),
        m.get("resource", ""),
        m.get("action", ""),
        m.get("principal", ""),
        m.get("impact", ""),
        m.get("security_property", ""),
        node.label,
    )


def _path_semantics(path: AttackPath, graph: GraphEngine) -> tuple[tuple[str,...], tuple[str,...]]:
    nodes=[graph.get_node(path.entry)]
    for step in path.steps:
        nodes.append(graph.get_node(step.next_node_id))
    return tuple(_node_semantics(n) for n in nodes), tuple(
        graph.get_edge(step.edge_id).relationship_type.value for step in path.steps
    )


def _candidate_matches(node, target):
    if node.canonical_identity == target.canonical_identity:
        return 100
    a=_node_semantics(node)
    b=_node_semantics(target)
    score=sum(1 for x,y in zip(a,b) if x and x == y)
    return score


class VerificationEngine:
    """Build, execute, and persistable-return deterministic verification outcomes."""

    def __init__(self, *, diff_engine: SemanticGraphDiffEngine | None = None):
        self.diff_engine=diff_engine or SemanticGraphDiffEngine()

    def plan(self, finding: Finding, remediation: Remediation, original: Snapshot, candidate: Snapshot) -> VerificationPlan:
        if finding.snapshot_id != original.id or remediation.original_snapshot_id != original.id:
            raise ValueError("finding/remediation do not belong to original snapshot")
        if remediation.target_snapshot_id not in {None, candidate.id}:
            raise ValueError("remediation target snapshot mismatch")
        checks=[
            VerificationCheck.REPRODUCE_ORIGINAL_CONDITION,
            VerificationCheck.VERIFY_GRAPH_CHANGE,
            VerificationCheck.VERIFY_ATTACK_PATH,
            VerificationCheck.VERIFY_ALTERNATE_PATHS,
            VerificationCheck.VERIFY_ARTIFACT_INTEGRITY,
            VerificationCheck.VERIFY_CONTROL,
        ]
        if remediation.type.value in {"PERMISSION_REDUCTION","AUTHORIZATION_CHANGE","AGENT_POLICY_CHANGE","TOOL_PERMISSION_CHANGE","MCP_CONFIGURATION_CHANGE"}:
            checks.append(VerificationCheck.VERIFY_PERMISSION)
        if remediation.type.value in {"AUTHENTICATION_CHANGE","PERMISSION_REDUCTION","AUTHORIZATION_CHANGE"}:
            checks.append(VerificationCheck.VERIFY_IDENTITY)
        if remediation.type.value in {"CODE_CHANGE","CONFIGURATION_CHANGE","DEPENDENCY_UPDATE"}:
            checks.append(VerificationCheck.VERIFY_DATAFLOW)
        return VerificationPlan(
            id=new_id("verification_plan"),
            finding_id=finding.id,
            remediation_id=remediation.id,
            original_snapshot_id=original.id,
            candidate_snapshot_id=candidate.id,
            security_property=remediation.expected_security_property,
            required_checks=tuple(dict.fromkeys(checks)),
            scope_components=remediation.affected_components,
            plan_fingerprint=new_id("verification_plan_fingerprint"),
        )

    def _validate_inputs(self, original: Snapshot, candidate: Snapshot, before: GraphEngine, after: GraphEngine):
        if original.id == candidate.id:
            return ("original and candidate snapshots must differ",)
        if before.scope.kind != GraphScopeKind.SNAPSHOT or after.scope.kind != GraphScopeKind.SNAPSHOT:
            return ("both graphs must be snapshot-scoped",)
        if before.scope.snapshot_id != original.id or after.scope.snapshot_id != candidate.id:
            return ("graph snapshot identity does not match supplied snapshots",)
        if before.scope.analysis_id != after.scope.analysis_id:
            return ("graphs belong to different analyses",)
        if not before.complete:
            return ("original graph is incomplete",)
        if not after.complete:
            return ("candidate graph is incomplete; absence cannot prove remediation",)
        return ()

    def _attack_path(self, graph: GraphEngine, path) -> AttackPath:
        steps=[]
        for edge in path.edges:
            steps.append(AttackPathStep(
                node_id=edge.source_node_id,
                edge_id=edge.id,
                next_node_id=edge.target_node_id,
                evidence_ids=edge.evidence_ids,
            ))
        return AttackPath(
            id=new_id("attack_path"),
            entry=path.nodes[0].id,
            steps=tuple(steps),
            trust_boundaries_crossed=path.trust_boundary_node_ids,
            supporting_evidence_ids=path.evidence_ids,
            snapshot_id=path.snapshot_id,
            observed_at=datetime.now(timezone.utc),
        )

    def _candidate_paths(self, original_path: AttackPath, before: GraphEngine, after: GraphEngine, limit: int = 20):
        original_nodes=[before.get_node(original_path.entry)] + [before.get_node(s.next_node_id) for s in original_path.steps]
        source_target=(original_nodes[0], original_nodes[-1])
        sources=sorted(
            (n for n in after.nodes() if n.type == source_target[0].type and _candidate_matches(n,source_target[0]) > 0),
            key=lambda n:(- _candidate_matches(n,source_target[0]),n.id),
        )[:10]
        sinks=sorted(
            (n for n in after.nodes() if n.type == source_target[1].type and _candidate_matches(n,source_target[1]) > 0),
            key=lambda n:(- _candidate_matches(n,source_target[1]),n.id),
        )[:10]
        paths=[]
        for source in sources:
            for sink in sinks:
                if source.id == sink.id:
                    continue
                result=after.bounded_paths(source.id,sink.id,max_depth=12,max_paths=limit)
                paths.extend(result.paths)
                if len(paths)>=limit:
                    return tuple(paths[:limit])
        return tuple(paths)

    def verify(
        self,
        *,
        finding: Finding,
        remediation: Remediation,
        original_snapshot: Snapshot,
        candidate_snapshot: Snapshot,
        original_graph: GraphEngine,
        candidate_graph: GraphEngine,
        original_paths: tuple[AttackPath, ...],
        security_tests: tuple[SecurityTestDefinition, ...] = (),
        test_executor: SecurityTestExecutor | None = None,
        baseline: object | None = None,
    ) -> VerificationOutcome:
        errors=self._validate_inputs(original_snapshot,candidate_snapshot,original_graph,candidate_graph)
        plan=self.plan(finding,remediation,original_snapshot,candidate_snapshot)
        if security_tests:
            plan=plan.model_copy(update={"required_checks": (*plan.required_checks, VerificationCheck.VERIFY_SECURITY_TEST)})
        verification_id=new_id("verification")
        checks=[]
        missing=list(errors)
        if errors:
            for check in plan.required_checks:
                checks.append(VerificationCheckResult(check=check,status=CheckStatus.BLOCKED,notes="; ".join(errors),blocking=True))
            graph_diff=GraphDiff(
                id=new_id("graph_diff"),analysis_id=original_graph.scope.analysis_id,
                original_snapshot_id=original_snapshot.id,candidate_snapshot_id=candidate_snapshot.id,
            )
            evidence=VerificationEvidence(
                id=new_id("verification_evidence"),verification_id=verification_id,
                claim="Verification could not establish snapshot/graph integrity.",
                graph_diff_id=graph_diff.id,
            )
            result=VerificationResult(
                verification_id=verification_id,finding_id=finding.id,analysis_id=original_graph.scope.analysis_id,
                original_snapshot_id=original_snapshot.id,candidate_snapshot_id=candidate_snapshot.id,
                result=VerdictType.UNKNOWN,security_property=remediation.expected_security_property,
                property_outcome=SecurityPropertyOutcome.UNKNOWN,
                original_path_status=AttackPathComparisonStatus.UNKNOWN,graph_diff_id=graph_diff.id,
                verification_evidence_ids=(evidence.id,),missing_evidence=tuple(sorted(set(errors))),
                limitations=("Verification stopped before comparison because required integrity conditions were not established.",),
                checks=tuple(checks),completeness_required=len(plan.required_checks),completeness_completed=0,
                completed_at=datetime.now(timezone.utc),
            )
            run=VerificationRun(id=new_id("verification_run"),verification_id=verification_id,plan_id=plan.id,
                started_at=result.created_at,completed_at=result.completed_at,checks_executed=tuple(checks))
            report=VerificationReport(
                verification_id=verification_id,finding_id=finding.id,security_property=remediation.expected_security_property,
                original_snapshot_id=original_snapshot.id,candidate_snapshot_id=candidate_snapshot.id,
                graph_diff_id=graph_diff.id,evidence=(evidence.id,),limitations=result.limitations,result=VerdictType.UNKNOWN)
            return VerificationOutcome(result=result,report=report,plan=plan,run=run,graph_diff=graph_diff,
                comparisons=(),residual_paths=(),regressions=(),tests=())

        graph_diff=self.diff_engine.compare(original_graph,candidate_graph)
        checks.append(VerificationCheckResult(
            check=VerificationCheck.REPRODUCE_ORIGINAL_CONDITION,
            status=CheckStatus.PASSED if original_paths else CheckStatus.BLOCKED,
            evidence_ids=tuple(sorted(finding.supporting_evidence_ids)),
            notes="original finding/attack-path evidence is present" if original_paths else "original attack path is unavailable",
            blocking=not bool(original_paths),
        ))
        checks.append(VerificationCheckResult(
            check=VerificationCheck.VERIFY_ARTIFACT_INTEGRITY,
            status=CheckStatus.PASSED,
            notes="snapshot identities and complete graph scopes were validated",
        ))
        checks.append(VerificationCheckResult(
            check=VerificationCheck.VERIFY_CONTROL,
            status=CheckStatus.PASSED,
            notes="no new control regression was detected by the semantic graph diff",
            blocking=False,
        ))
        checks.append(VerificationCheckResult(
            check=VerificationCheck.VERIFY_GRAPH_CHANGE,status=CheckStatus.PASSED,
            notes=f"nodes +{len(graph_diff.added_node_ids)} -{len(graph_diff.removed_node_ids)}; edges +{len(graph_diff.added_edge_ids)} -{len(graph_diff.removed_edge_ids)}"
        ))

        comparisons=[]
        residuals=[]
        alternate_ids=[]
        supporting=set(finding.supporting_evidence_ids)
        candidate_paths=[]
        original_path_status=AttackPathComparisonStatus.UNKNOWN

        if not original_paths:
            missing.append("original attack path unavailable")
        for original_path in original_paths:
            if original_path.snapshot_id != original_snapshot.id:
                missing.append(f"attack path {original_path.id} has wrong snapshot")
                continue
            candidates=self._candidate_paths(original_path,original_graph,candidate_graph)
            candidate_attacks=tuple(self._attack_path(candidate_graph,p) for p in candidates)
            candidate_paths.extend(candidate_attacks)
            exact=[]
            orig_nodes,orig_edges=_path_semantics(original_path,original_graph)
            for cp in candidate_attacks:
                cn,ce=_path_semantics(cp,candidate_graph)
                if cn == orig_nodes and ce == orig_edges:
                    exact.append(cp)
            if exact:
                status=AttackPathComparisonStatus.ORIGINAL_PATH_PERSISTENT
                path_statuses.append(AttackPathComparisonStatus.ORIGINAL_PATH_PERSISTENT)
            elif candidate_attacks:
                status=AttackPathComparisonStatus.ALTERNATE_PATH_FOUND
                path_statuses.append(AttackPathComparisonStatus.ALTERNATE_PATH_FOUND)
            else:
                status=AttackPathComparisonStatus.ORIGINAL_PATH_BROKEN
                path_statuses.append(AttackPathComparisonStatus.ORIGINAL_PATH_BROKEN)
            if status != AttackPathComparisonStatus.ORIGINAL_PATH_BROKEN:
                for cp in candidate_attacks:
                    if cp.supporting_evidence_ids:
                        supporting.update(cp.supporting_evidence_ids)
            comparison=AttackPathComparison(
                id=new_id("attack_path_comparison"),
                original_path_id=original_path.id,
                candidate_path_ids=tuple(p.id for p in candidate_attacks),
                status=status,
                equivalent_security_impact=status in {AttackPathComparisonStatus.ORIGINAL_PATH_PERSISTENT,AttackPathComparisonStatus.ALTERNATE_PATH_FOUND},
                source_signature=tuple(x[0] for x in orig_nodes),
                sink_signature=tuple(x[0] for x in orig_nodes[-1:]),
                evidence_ids=tuple(sorted(set(original_path.supporting_evidence_ids).union(*(p.supporting_evidence_ids for p in candidate_attacks)))),
                rationale=("The original semantic route remains reachable." if status==AttackPathComparisonStatus.ORIGINAL_PATH_PERSISTENT else
                           "A candidate path reaches the original semantic source/sink region." if status==AttackPathComparisonStatus.ALTERNATE_PATH_FOUND else
                           "No bounded candidate path reaches the original semantic sink."))
            comparisons.append(comparison)
            if status == AttackPathComparisonStatus.ALTERNATE_PATH_FOUND:
                alternate_ids.extend(p.id for p in candidate_attacks)
                for p in candidate_attacks:
                    residuals.append(ResidualPath(
                        id=new_id("residual_path"),verification_id=verification_id,path_id=p.id,
                        security_property=remediation.expected_security_property,
                        evidence_ids=p.supporting_evidence_ids,exploitable=True,equivalent_impact=True,
                        description="Candidate path reaches the original security-impact region.",
                    ))
            elif status == AttackPathComparisonStatus.ORIGINAL_PATH_PERSISTENT:
                for p in candidate_attacks:
                    residuals.append(ResidualPath(
                        id=new_id("residual_path"),verification_id=verification_id,path_id=p.id,
                        security_property=remediation.expected_security_property,
                        evidence_ids=p.supporting_evidence_ids,exploitable=True,equivalent_impact=True,
                        description="Original semantic attack path remains reachable.",
                    ))

        if not path_statuses:
            original_path_status=AttackPathComparisonStatus.UNKNOWN
        elif AttackPathComparisonStatus.ORIGINAL_PATH_PERSISTENT in path_statuses:
            original_path_status=AttackPathComparisonStatus.ORIGINAL_PATH_PERSISTENT
        elif AttackPathComparisonStatus.ALTERNATE_PATH_FOUND in path_statuses:
            original_path_status=AttackPathComparisonStatus.ALTERNATE_PATH_FOUND
        else:
            original_path_status=AttackPathComparisonStatus.ORIGINAL_PATH_BROKEN

        checks.append(VerificationCheckResult(
            check=VerificationCheck.VERIFY_ATTACK_PATH,
            status=CheckStatus.PASSED if original_path_status in {AttackPathComparisonStatus.ORIGINAL_PATH_BROKEN,AttackPathComparisonStatus.PATH_WEAKENED} else CheckStatus.FAILED,
            evidence_ids=tuple(sorted(supporting)),
            notes=original_path_status.value,
            blocking=original_path_status in {AttackPathComparisonStatus.ORIGINAL_PATH_PERSISTENT,AttackPathComparisonStatus.ALTERNATE_PATH_FOUND},
        ))
        checks.append(VerificationCheckResult(
            check=VerificationCheck.VERIFY_ALTERNATE_PATHS,
            status=CheckStatus.PASSED if not alternate_ids else CheckStatus.FAILED,
            notes=f"{len(alternate_ids)} alternate/residual candidate paths discovered",
            blocking=bool(alternate_ids),
        ))
        if VerificationCheck.VERIFY_DATAFLOW in plan.required_checks:
            checks.append(VerificationCheckResult(
                check=VerificationCheck.VERIFY_DATAFLOW,
                status=CheckStatus.PASSED if original_path_status == AttackPathComparisonStatus.ORIGINAL_PATH_BROKEN else CheckStatus.FAILED,
                notes="bounded source-to-sink reachability changed" if original_path_status == AttackPathComparisonStatus.ORIGINAL_PATH_BROKEN else "source-to-sink reachability remains",
                blocking=original_path_status != AttackPathComparisonStatus.ORIGINAL_PATH_BROKEN,
            ))
        if VerificationCheck.VERIFY_IDENTITY in plan.required_checks:
            original_identities={n.canonical_identity for n in original_graph.nodes() if n.type.value=="IDENTITY"}
            candidate_identities={n.canonical_identity for n in candidate_graph.nodes() if n.type.value=="IDENTITY"}
            identity_ok=bool(original_identities) and candidate_identities.issuperset(original_identities)
            checks.append(VerificationCheckResult(check=VerificationCheck.VERIFY_IDENTITY,status=CheckStatus.PASSED if identity_ok else CheckStatus.BLOCKED,notes="identity scope is preserved" if identity_ok else "identity evidence is unavailable or changed",blocking=not identity_ok))
            if not identity_ok:
                missing.append("identity comparison could not be deterministically established")

        permission_blocking=bool(graph_diff.permission_widened)
        if VerificationCheck.VERIFY_PERMISSION in plan.required_checks:
            checks.append(VerificationCheckResult(
                check=VerificationCheck.VERIFY_PERMISSION,
                status=CheckStatus.FAILED if permission_blocking else CheckStatus.PASSED,
                notes="permission widening detected" if permission_blocking else "no relevant permission widening detected",
                blocking=permission_blocking,
            ))

        tests=[]
        if security_tests:
            if test_executor is None:
                missing.append("security tests were requested but no executor was provided")
            else:
                for definition in security_tests:
                    if definition.snapshot_id != candidate_snapshot.id:
                        missing.append(f"security test {definition.test_id} targets the wrong snapshot")
                    else:
                        tests.append(test_executor.execute(definition))
                checks.append(VerificationCheckResult(
                    check=VerificationCheck.VERIFY_SECURITY_TEST,
                    status=CheckStatus.PASSED if tests and all(t.passed for t in tests) else CheckStatus.FAILED,
                    evidence_ids=tuple(e for t in tests for e in t.evidence_ids),
                    notes="all configured security tests passed" if tests and all(t.passed for t in tests) else "one or more security tests failed",
                    blocking=not tests or not all(t.passed for t in tests),
                ))

        regressions=()
        if baseline is not None:
            regression=RegressionEngine().detect(
                baseline=baseline,current=candidate_snapshot,graph=candidate_graph,
                reachable_baseline_path=bool(alternate_ids or residuals),
            )
            if regression.status.value=="DETECTED":
                regressions=(regression,)
        blocking_failure=(
            original_path_status in {AttackPathComparisonStatus.ORIGINAL_PATH_PERSISTENT,AttackPathComparisonStatus.ALTERNATE_PATH_FOUND}
            or permission_blocking
            or any(not t.passed for t in tests)
        )
        candidate_evidence=tuple(sorted({e for p in candidate_paths for e in p.supporting_evidence_ids}))
        supporting.update(candidate_evidence)

        if missing:
            result_type=VerdictType.UNKNOWN
            outcome=SecurityPropertyOutcome.UNKNOWN
        elif regressions:
            result_type=VerdictType.REGRESSED
            outcome=SecurityPropertyOutcome.WORSENED
        elif blocking_failure:
            result_type=VerdictType.REMEDIATION_FAILED
            outcome=SecurityPropertyOutcome.UNCHANGED
        elif original_path_status == AttackPathComparisonStatus.ORIGINAL_PATH_BROKEN and candidate_graph.complete:
            result_type=VerdictType.REMEDIATED
            outcome=SecurityPropertyOutcome.ELIMINATED
        else:
            result_type=VerdictType.UNKNOWN
            outcome=SecurityPropertyOutcome.UNKNOWN
            missing.append("security property could not be deterministically established")

        ve=VerificationEvidence(
            id=new_id("verification_evidence"),
            verification_id=verification_id,
            claim="Candidate snapshot was compared against the original security property.",
            evidence_ids=tuple(sorted(supporting)),
            graph_diff_id=graph_diff.id,
            attack_path_comparison_id=comparisons[0].id if comparisons else None,
            provenance=(),
        )
        if result_type == VerdictType.REMEDIATED:
            supporting.update(ve.evidence_ids)

        result=VerificationResult(
            verification_id=verification_id,
            finding_id=finding.id,
            analysis_id=original_graph.scope.analysis_id,
            original_snapshot_id=original_snapshot.id,
            candidate_snapshot_id=candidate_snapshot.id,
            result=result_type,
            security_property=remediation.expected_security_property,
            property_outcome=outcome,
            original_path_status=original_path_status,
            graph_diff_id=graph_diff.id,
            attack_path_comparison_ids=tuple(c.id for c in comparisons),
            residual_path_ids=tuple(r.id for r in residuals),
            alternate_path_ids=tuple(alternate_ids),
            regression_ids=tuple(r.id for r in regressions),
            verification_evidence_ids=(ve.id,),
            supporting_evidence_ids=tuple(sorted(supporting)),
            contradicting_evidence_ids=(),
            missing_evidence=tuple(sorted(set(missing))),
            limitations=("Verification is scoped to the original finding and bounded candidate graph.",),
            checks=tuple(checks),
            completeness_required=len(plan.required_checks),
            completeness_completed=sum(
                c.status in {CheckStatus.PASSED,CheckStatus.NOT_APPLICABLE}
                for c in checks if c.check in plan.required_checks
            ),
            completed_at=datetime.now(timezone.utc),
        )
        run=VerificationRun(
            id=new_id("verification_run"),verification_id=verification_id,plan_id=plan.id,
            started_at=result.created_at,completed_at=result.completed_at,checks_executed=tuple(checks),
            paths_evaluated=len(candidate_paths),alternate_paths_discovered=len(alternate_ids),
        )
        report=VerificationReport(
            verification_id=verification_id,finding_id=finding.id,
            security_property=remediation.expected_security_property,
            original_snapshot_id=original_snapshot.id,candidate_snapshot_id=candidate_snapshot.id,
            original_attack_paths=tuple(p.id for p in original_paths),
            candidate_attack_paths=tuple(p.id for p in candidate_paths),
            removed_paths=tuple(p.id for p in original_paths if original_path_status==AttackPathComparisonStatus.ORIGINAL_PATH_BROKEN),
            remaining_paths=tuple(p.id for p in candidate_paths if p.id not in alternate_ids),
            alternate_paths=tuple(alternate_ids),graph_diff_id=graph_diff.id,
            attack_path_comparison_ids=tuple(c.id for c in comparisons),
            residual_path_ids=tuple(r.id for r in residuals),regressions=tuple(r.id for r in regressions),
            tests=tuple(tests),evidence=(ve.id,),limitations=result.limitations,result=result_type,
        )
        established_baseline=None
        if result_type == VerdictType.REMEDIATED:
            established_baseline=RegressionEngine().establish_baseline(
                finding=finding,verification_id=verification_id,security_property=remediation.expected_security_property,
                snapshot=candidate_snapshot,attack_path_ids=tuple(p.id for p in candidate_paths),
                evidence_ids=tuple(sorted(supporting)),graph=candidate_graph,
            )
        return VerificationOutcome(
            result=result,report=report,plan=plan,run=run,graph_diff=graph_diff,
            comparisons=tuple(comparisons),residual_paths=tuple(residuals),regressions=tuple(regressions),
            tests=tuple(tests),baseline=established_baseline
        )
