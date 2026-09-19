from fas.domain.common import GraphNodeType, RelationshipType
from fas.graph import GraphEngine, ResultStatus
from tests.fixtures.graph.scenarios import (
    scenario_agent_tool_chain,
    scenario_authentication_boundary,
    scenario_code_flow,
    scenario_conflicting_evidence,
    scenario_cyclic_graph,
    scenario_mcp_chain,
    scenario_multiple_evidence_sources,
    scenario_remediation_diff,
    scenario_residual_path,
)


def test_realistic_security_scenarios_are_structurally_queryable():
    scenarios = (
        scenario_code_flow(),
        scenario_authentication_boundary(),
        scenario_agent_tool_chain(),
        scenario_mcp_chain(),
        scenario_multiple_evidence_sources(),
        scenario_conflicting_evidence(),
        scenario_cyclic_graph(),
    )
    for graph in scenarios:
        assert graph.validate().valid
        assert graph.nodes()
        assert graph.edges()


def test_remediation_fixture_removes_structural_edge():
    original, patched = scenario_remediation_diff()
    diff = GraphEngine.diff(original, patched)
    assert diff.removed_edges
    assert not diff.added_edges


def test_residual_fixture_retains_alternate_structure():
    original, patched = scenario_residual_path()
    agent = next(node for node in original.nodes() if node.type == GraphNodeType.AGENT)
    resource = next(node for node in original.nodes() if node.canonical_identity.endswith(":production"))
    assert patched.has_path(agent.id, resource.id) is True

    patched_agent = next(node for node in patched.nodes() if node.type == GraphNodeType.AGENT)
    patched_resource = next(node for node in patched.nodes() if node.canonical_identity.endswith(":production"))
    result = patched.shortest_path(patched_agent.id, patched_resource.id)
    assert result.status == ResultStatus.PARTIAL
    assert result.paths
