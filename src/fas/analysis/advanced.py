"""Bounded deterministic advanced graph analysis."""
from __future__ import annotations
from dataclasses import dataclass
from fas.domain.common import GraphNodeType, NodeId, RelationshipType
from fas.graph import GraphEngine, GraphPath, ResultStatus

FLOW=frozenset({
    RelationshipType.FLOWS_TO,RelationshipType.CALLS,RelationshipType.INVOKES,
    RelationshipType.EXPOSES,RelationshipType.CAN_USE,RelationshipType.EXECUTES,
    RelationshipType.CAN_ACCESS,RelationshipType.CAN_MODIFY,RelationshipType.READS,
    RelationshipType.WRITES,RelationshipType.PASSES_THROUGH,
})

@dataclass(frozen=True, slots=True)
class AnalysisSignal:
    kind:str
    source_id:NodeId
    target_id:NodeId
    path:GraphPath|None
    status:ResultStatus
    evidence_ids:tuple[str,...]

@dataclass(frozen=True, slots=True)
class AttackSurface:
    exposed_endpoints:tuple[NodeId,...]
    agents:tuple[NodeId,...]
    tools:tuple[NodeId,...]
    mcp:tuple[NodeId,...]
    secrets:tuple[NodeId,...]
    boundaries:tuple[NodeId,...]
    complete:bool

class AdvancedAnalysisEngine:
    def __init__(self,graph:GraphEngine,max_pairs:int=256):
        if max_pairs<1: raise ValueError("max_pairs must be positive")
        self.graph,self.max_pairs=graph,max_pairs

    def attack_surface(self)->AttackSurface:
        nodes=self.graph.nodes()
        def pick(types):
            return tuple(n.id for n in nodes if n.type in types)
        return AttackSurface(
            exposed_endpoints=pick({GraphNodeType.ENDPOINT}),
            agents=pick({GraphNodeType.AGENT,GraphNodeType.AGENT_TASK}),
            tools=pick({GraphNodeType.TOOL,GraphNodeType.MCP_TOOL}),
            mcp=pick({GraphNodeType.MCP_SERVER,GraphNodeType.MCP_TOOL}),
            secrets=pick({GraphNodeType.SECRET,GraphNodeType.CREDENTIAL}),
            boundaries=pick({GraphNodeType.TRUST_BOUNDARY}),
            complete=self.graph.complete,
        )

    def paths(self,source_types,f_sink_types,*,kind="REACHABILITY",relationships=FLOW,max_depth=None)->tuple[AnalysisSignal,...]:
        sources=tuple(n for n in self.graph.nodes() if n.type in source_types)
        sinks=tuple(n for n in self.graph.nodes() if n.type in f_sink_types)
        out=[]; pairs=0
        for source in sources:
            for sink in sinks:
                if source.id==sink.id: continue
                pairs+=1
                if pairs>self.max_pairs:
                    return (*out,AnalysisSignal(kind+"_LIMIT",source.id,sink.id,None,ResultStatus.TRUNCATED,()))
                kwargs={"allowed_relationship_types":relationships}\n                if max_depth is not None: kwargs["max_depth"]=max_depth\n                result=self.graph.shortest_path(source.id,sink.id,**kwargs)
                for path in result.paths:
                    evidence=tuple(sorted({e for n in path.nodes for e in n.evidence_ids}|{e for e in path.edges for e in e.evidence_ids}))
                    out.append(AnalysisSignal(kind,source.id,sink.id,path,result.status,evidence))
        return tuple(out)

    def analyze(self)->tuple[AnalysisSignal,...]:
        return (
            *self.paths({GraphNodeType.ENDPOINT,GraphNodeType.DATA_ASSET},{GraphNodeType.SECRET,GraphNodeType.CREDENTIAL,GraphNodeType.INFRASTRUCTURE_RESOURCE},kind="DATA_REACHABILITY"),
            *self.paths({GraphNodeType.IDENTITY,GraphNodeType.PRINCIPAL,GraphNodeType.ROLE},{GraphNodeType.DATA_ASSET,GraphNodeType.SERVICE,GraphNodeType.SECRET},kind="PRIVILEGE_REACHABILITY"),
            *self.paths({GraphNodeType.AGENT_TASK,GraphNodeType.DATA_ASSET},{GraphNodeType.TOOL,GraphNodeType.MCP_SERVER,GraphNodeType.MCP_TOOL,GraphNodeType.SECRET},kind="AGENT_TOOL_REACHABILITY"),
        )
