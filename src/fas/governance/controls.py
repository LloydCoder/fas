"""Machine-readable governance and assurance contracts."""
from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum

class AssessmentStatus(StrEnum):
    NOT_ASSESSED="NOT_ASSESSED"
    SUPPORTED="SUPPORTED"
    PARTIAL="PARTIAL"
    NOT_SUPPORTED="NOT_SUPPORTED"
    UNKNOWN="UNKNOWN"

class Framework(StrEnum):
    NIST_SSDF_1_1="NIST.SP-800-218.1.1"
    NIST_SSDF_1_2_DRAFT="NIST.SP-800-218.1.2-DRAFT"
    NIST_SSDF_AI="NIST.SP-800-218A"
    OWASP_ASVS_5_0="OWASP.ASVS.5.0.0"

@dataclass(frozen=True, slots=True)
class Control:
    control_id:str
    title:str
    objective:str
    framework:Framework
    reference:str
    required_evidence:tuple[str,...]
    def __post_init__(self)->None:
        if not self.control_id or not self.title or not self.reference: raise ValueError("control identity is required")
        if not self.required_evidence: raise ValueError("control requires evidence definition")

@dataclass(frozen=True, slots=True)
class ControlAssessment:
    control_id:str
    status:AssessmentStatus
    evidence_ids:tuple[str,...]=()
    limitations:tuple[str,...]=()
    rationale:str=""
    def __post_init__(self)->None:
        if self.status==AssessmentStatus.SUPPORTED and not self.evidence_ids:
            raise ValueError("SUPPORTED control assessment requires evidence")

@dataclass(frozen=True, slots=True)
class PolicyDecision:
    policy_id:str
    allowed:bool
    reason:str
    subject:str
    tenant_id:str
    evidence_ids:tuple[str,...]=()

@dataclass(frozen=True, slots=True)
class ControlCatalog:
    controls:tuple[Control,...]
    def get(self,control_id:str)->Control:
        for control in self.controls:
            if control.control_id==control_id: return control
        raise KeyError(control_id)
    def frameworks(self)->tuple[Framework,...]:
        return tuple(sorted({control.framework for control in self.controls},key=lambda item:item.value))
