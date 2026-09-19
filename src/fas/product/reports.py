"""Evidence-linked report generation from persisted domain state."""
from __future__ import annotations
from datetime import datetime, timezone
from fas.domain import Report, new_id
from .storage import SQLiteStore

class ReportService:
    def __init__(self, store: SQLiteStore):
        self.store=store

    def generate(self, analysis_id: str, snapshot_id: str) -> Report:
        analysis=self.store.get("analyses",analysis_id)
        findings=self.store.list("findings","snapshot_id",snapshot_id)
        investigations=[]
        report={
            "schema_version":"1.0","analysis_id":analysis_id,"snapshot_id":snapshot_id,
            "executive_summary":{"scope":analysis.get("project"),"finding_count":len(findings),
                                "status":analysis.get("status")},
            "findings":findings,"investigations":investigations,
            "limitations":analysis.get("metadata",{}).get("limitations",""),
            "provenance":{"producer":"fas.report","generated_at":datetime.now(timezone.utc).isoformat()},
        }
        result=Report(id=new_id("report"),analysis_id=analysis_id,snapshot_id=snapshot_id,
                      title="FAS Security Analysis Report",finding_ids=tuple(f["id"] for f in findings),
                      generated_at=datetime.now(timezone.utc),format="json",content=report)
        self.store.put("reports",result.id,analysis_id,result.model_dump(mode="json"),result.generated_at.isoformat())
        return result
