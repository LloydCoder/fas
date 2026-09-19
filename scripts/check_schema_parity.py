"""Validate checked-in JSON Schema property/required sets against Pydantic domain models."""
import json
from pathlib import Path

from fas.domain import Project
from fas.domain.audit import AuditEvent, Report, ToolRun
from fas.domain.investigation import EvidenceRequest, InvestigationCase, InvestigationHypothesis, InvestigationResult, VerdictProposal
from fas.domain.verification import (
    AttackPathComparison, GraphDiff, Remediation, RegressionTest, ResidualPath,
    SecurityBaseline, SecurityRegression, SecurityTestDefinition, SecurityTestResult,
    Verification, VerificationEvidence, VerificationPlan, VerificationReport, VerificationResult,
    VerificationRun,
)

def check_schema(path, models):
    schema=json.loads(Path(path).read_text(encoding="utf-8"))
    failures=[]
    failures += check_schema("schemas/project.schema.json", {"Project":Project})
    for name, model in models.items():
        expected=model.model_json_schema()
        actual=schema.get("$defs",{}).get(name)
        if actual is None:
            failures.append(f"{path}: {name}: missing $defs entry")
            continue
        if set(expected.get("properties",{})) != set(actual.get("properties",{})):
            failures.append(f"{path}: {name}: property set mismatch")
        if not set(expected.get("required",[])).issubset(set(actual.get("required",[]))):
            failures.append(f"{path}: {name}: required schema fields are missing")
    return failures

def main():
    failures=[]
    failures += check_schema("schemas/investigation.schema.json", {
        "InvestigationCase":InvestigationCase,"InvestigationHypothesis":InvestigationHypothesis,
        "EvidenceRequest":EvidenceRequest,"InvestigationResult":InvestigationResult,"VerdictProposal":VerdictProposal,
    })
    failures += check_schema("schemas/audit.schema.json", {"AuditEvent":AuditEvent,"Report":Report,"ToolRun":ToolRun})
    failures += check_schema("schemas/phase5.schema.json", {
        "Remediation":Remediation,"Verification":Verification,"VerificationPlan":VerificationPlan,
        "VerificationRun":VerificationRun,"GraphDiff":GraphDiff,"AttackPathComparison":AttackPathComparison,
        "ResidualPath":ResidualPath,"VerificationEvidence":VerificationEvidence,
        "SecurityRegression":SecurityRegression,"RegressionTest":RegressionTest,"SecurityBaseline":SecurityBaseline,
        "SecurityTestDefinition":SecurityTestDefinition,"SecurityTestResult":SecurityTestResult,
        "VerificationResult":VerificationResult,"VerificationReport":VerificationReport,
    })
    if failures:
        raise SystemExit("\n".join(failures))
    print("Schema parity: PASS")

if __name__=="__main__":
    main()
