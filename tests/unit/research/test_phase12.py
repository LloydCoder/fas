from fas.research import AuthorityBoundary, Hypothesis, ResearchBudget, ResearchLoop, RequestKind

def test_research_loop_stays_non_authoritative():
    loop=ResearchLoop(ResearchBudget(max_requests=2))
    candidates=loop.propose("snapshot-a",[Hypothesis("h1","check access path")])
    run=loop.run("run-a","snapshot-a",candidates,lambda request: True)
    assert run.authoritative is False
    assert run.completed_requests==0
    assert run.requests[0].kind is RequestKind.RECHECK

def test_authority_boundary_rejects_autonomous_write():
    try:
        AuthorityBoundary.reject_authoritative_write()
    except PermissionError:
        pass
    else:
        raise AssertionError("autonomous authority boundary was bypassed")

def test_research_budget_bounds_candidates():
    loop=ResearchLoop(ResearchBudget(max_requests=2,max_hypotheses=2))
    hypotheses=[Hypothesis(f"h{i}",f"statement {i}") for i in range(10)]
    candidates=loop.propose("snapshot-a",hypotheses)
    assert len(candidates)==2
