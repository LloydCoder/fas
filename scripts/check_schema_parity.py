"""Fail CI when Phase 4 public model properties drift from the checked-in schema contract."""
import json
from pathlib import Path
from fas.domain.investigation import EvidenceRequest, InvestigationCase, InvestigationHypothesis, InvestigationResult, VerdictProposal

MODELS={"InvestigationCase":InvestigationCase,"InvestigationHypothesis":InvestigationHypothesis,"EvidenceRequest":EvidenceRequest,"InvestigationResult":InvestigationResult,"VerdictProposal":VerdictProposal}

def main():
    schema=json.loads(Path("schemas/investigation.schema.json").read_text(encoding="utf-8"))
    failures=[]
    for name,model in MODELS.items():
        expected=model.model_json_schema()
        actual=schema["$defs"].get(name)
        if actual is None:
            failures.append(f"{name}: missing $defs entry"); continue
        if set(expected.get("properties",{})) != set(actual.get("properties",{})):
            failures.append(f"{name}: property set mismatch")
        if set(expected.get("required",[])) != set(actual.get("required",[])):
            failures.append(f"{name}: required set mismatch")
    if failures:
        raise SystemExit("\n".join(failures))
    print("Phase 4 schema parity: PASS")

if __name__=="__main__":
    main()
