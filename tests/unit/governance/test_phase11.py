from hashlib import sha256
from fas.governance.bundle import build_bundle
from fas.governance.controls import AssessmentStatus, Control, ControlAssessment, Framework

def test_bundle_manifest_is_deterministic_and_verifiable():
    first=build_bundle("tenant-a","analysis-a",{"report.json":b"{}","evidence.json":b"evidence"})
    second=build_bundle("tenant-a","analysis-a",{"evidence.json":b"evidence","report.json":b"{}"})
    assert first.manifest_digest==second.manifest_digest
    assert first.verify()

def test_bundle_rejects_unsafe_paths():
    try:
        build_bundle("tenant-a","analysis-a",{"../secret":b"x"})
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe bundle path accepted")

def test_supported_control_requires_traceable_evidence():
    control=Control("CTRL-1","Example","objective",Framework.OWASP_ASVS_5_0,"v5.0.0-example",("evidence",))
    try:
        ControlAssessment(control.control_id,AssessmentStatus.SUPPORTED)
    except ValueError:
        pass
    else:
        raise AssertionError("supported assessment without evidence accepted")
