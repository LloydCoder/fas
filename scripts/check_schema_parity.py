"""Fail CI when Phase 4 public model properties drift from the checked-in schema contract."""
import json
from pathlib import Path
from fas.domain.investigation import EvidenceRequest, InvestigationCase, InvestigationHypothesis, InvestigationResult, VerdictProposal
from fas.domain.audit import AuditEvent, Report, ToolRun

MODELS={"InvestigationCase":InvestigationCase,"InvestigationHypothesis":InvestigationHypothesis,"EvidenceRequest":EvidenceRequest,"InvestigationResult":InvestigationResult,"VerdictProposal":VerdictProposal}
AUDIT_MODELS={"AuditEvent":AuditEvent,"Report":Report,"ToolRun":ToolRun}

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
    audit=json.loads(Path("schemas/audit.schema.json").read_text(encoding="utf-8"))
    for name,model in AUDIT_MODELS.items():
        expected=model.model_json_schema(); actual=audit["$defs"].get(name)
        if actual is None or set(expected.get("properties",{})) != set(actual.get("properties",{})) or set(expected.get("required",[])) != set(actual.get("required",[])):
            failures.append(f"{name}: schema drift")
    if failures:
        raise SystemExit("\n".join(failures))
    print("Phase 4 schema parity: PASS")

if __name__=="__main__":
    main()
