from tests.fixtures.graph.scenarios import scenario_agent_tool_chain, scenario_code_flow
from fas.analysis.advanced import AdvancedAnalysisEngine
from fas.domain.common import GraphNodeType

def test_agent_tool_reachability_is_evidence_backed():
    graph=scenario_agent_tool_chain()
    result=AdvancedAnalysisEngine(graph,max_pairs=32).paths(
        {GraphNodeType.DATA_ASSET},{GraphNodeType.TOOL,GraphNodeType.SECRET},kind="AGENT_TOOL_REACHABILITY")
    assert result
    assert all(item.evidence_ids for item in result if item.path is not None)

def test_attack_surface_is_bounded_and_snapshot_scoped():
    graph=scenario_agent_tool_chain()
    surface=AdvancedAnalysisEngine(graph).attack_surface()
    assert surface.agents and surface.tools
    assert surface.complete is False

def test_code_flow_without_sensitive_sink_does_not_create_signal():
    graph=scenario_code_flow()
    result=AdvancedAnalysisEngine(graph).paths(
        {GraphNodeType.ENDPOINT},{GraphNodeType.SECRET,GraphNodeType.CREDENTIAL},kind="DATA_REACHABILITY")
    assert result == ()
