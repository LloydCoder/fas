import json
from fas.collectors import CollectionContext
from fas.adapters import GitleaksAdapter,SarifAdapter,SemgrepAdapter,TrivyAdapter

def _context(tmp_path):
    return CollectionContext(analysis_id="analysis_01J00000000000000000000000",snapshot_id="snapshot_01J00000000000000000000000",root=tmp_path,repository="fixture")

def test_semgrep_adapter(tmp_path):
    observations=SemgrepAdapter().parse({"results":[{"check_id":"python.lang.security.audit","path":"app.py","start":{"line":10,"col":3},"end":{"line":10,"col":12},"extra":{"message":"unsafe sink","severity":"WARNING","metadata":{"cwe":["CWE-78"]}}}]},_context(tmp_path))
    assert len(observations)==1
    assert observations[0].observed_value["check_id"]=="python.lang.security.audit"

def test_trivy_adapter(tmp_path):
    observations=TrivyAdapter().parse({"Results":[{"Target":"app","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgName":"demo","InstalledVersion":"1.0.0","FixedVersion":"1.0.1","Severity":"HIGH"}]}]},_context(tmp_path))
    assert observations[0].observed_value["vulnerability_id"]=="CVE-2026-0001"

def test_gitleaks_adapter_does_not_store_secret(tmp_path):
    observations=GitleaksAdapter().parse([{"RuleID":"aws","Description":"AWS key","File":"app.py","StartLine":4,"EndLine":4,"Secret":"SUPER-SECRET","Match":"api_key=SUPER-SECRET","Fingerprint":"fp"}],_context(tmp_path))
    assert "SUPER-SECRET" not in json.dumps(observations[0].model_dump(mode="json"))
    assert observations[0].metadata["secret_material_omitted"]=="true"

def test_sarif_adapter(tmp_path):
    observations=SarifAdapter().parse({"version":"2.1.0","runs":[{"tool":{"driver":{"name":"demo","semanticVersion":"1.0"}},"results":[{"ruleId":"R1","message":{"text":"problem"}}]}]},_context(tmp_path))
    assert observations[0].source=="demo"
