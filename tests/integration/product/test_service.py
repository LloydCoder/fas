from pathlib import Path

from fas.product.config import Settings
from fas.product.service import ProductService


def test_product_service_analysis_persists_snapshot_and_report(tmp_path: Path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    service = ProductService(
        Settings(database_url=f"sqlite:///{tmp_path / "fas.db"}", object_store_path=str(tmp_path / "objects"))
    )
    project = service.create_project("fixture", str(tmp_path))
    result = service.analyze_sync(project.id, tmp_path)

    analysis = service.get_analysis(result["analysis"]["id"])
    assert analysis.snapshot_ids
    assert analysis.status.value == "PARTIAL"
    assert result["snapshot"]["id"] == analysis.snapshot_ids[0]

    report = service.report(analysis.id)
    assert report["analysis_id"] == analysis.id
    assert report["snapshot_id"] == analysis.snapshot_ids[0]
