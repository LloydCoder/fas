"""Stable benchmark-compatible result projection."""
from __future__ import annotations
def benchmark_projection(analysis: dict, findings: list[dict], *, verification=None) -> dict:
    return {"schema_version":"1.0","analysis_id":analysis["id"],"snapshot_id":analysis["snapshot_ids"][-1] if analysis["snapshot_ids"] else None,
            "findings":findings,"verification":verification,"provenance":{"producer":"fas","mode":"deterministic"}}
