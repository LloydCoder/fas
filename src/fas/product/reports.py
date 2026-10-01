"""Evidence-linked report generation from persisted domain state."""
from __future__ import annotations
from datetime import datetime, timezone
from fas.domain import AuditEvent, Report, new_id
from .storage import SQLiteStore

class ReportService:
    def __init__(self, store: SQLiteStore, tenant_id: str = "local"):
        self.store=store
        self.tenant_id=tenant_id

    def generate(self, analysis_id: str, snapshot_id: str) -> Report:
        analysis=self.store.get("analyses",analysis_id,tenant_id=self.tenant_id)
        findings=self.store.list("findings","snapshot_id",snapshot_id,tenant_id=self.tenant_id)
        investigations=[]
        metadata=analysis.get("metadata",{})
        status=analysis.get("status","UNKNOWN")
        completeness=metadata.get("analysis_completeness","UNKNOWN")
        report={
            "schema_version":"1.0","analysis_id":analysis_id,"snapshot_id":snapshot_id,
            "executive_summary":{"scope":analysis.get("project"),"finding_count":len(findings),
                                "status":status,"completeness":completeness,
                                "clean_claim_permitted": status == "VERIFIED" and completeness == "COMPLETE"},
            "findings":findings,"investigations":investigations,
            "limitations":metadata.get("limitations",""),
            "provenance":{"producer":"fas.report","generated_at":datetime.now(timezone.utc).isoformat()},
        }
        result=Report(id=new_id("report"),analysis_id=analysis_id,snapshot_id=snapshot_id,
                      title="FAS Security Analysis Report",finding_ids=tuple(f["id"] for f in findings),
                      generated_at=datetime.now(timezone.utc),format="json",content=report)
        self.store.put("reports",result.id,analysis_id,result.model_dump(mode="json"),result.generated_at.isoformat(),tenant_id=self.tenant_id)
        event=AuditEvent(id=new_id("audit_event"),analysis_id=analysis_id,snapshot_id=snapshot_id,
                         event_type="REPORT_GENERATED",actor="fas",subject_id=result.id,payload={"format":"json"})
        self.store.append_audit(event.model_dump(mode="json"),tenant_id=self.tenant_id)
        return result
