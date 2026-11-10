from pathlib import Path

from fas.product.config import Settings
from fas.product.service import ProductService


def test_product_service_analysis_persists_snapshot_and_report(tmp_path: Path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    service = ProductService(
        Settings(database_url=f'sqlite:///{tmp_path / "fas.db"}', object_store_path=str(tmp_path / "objects"))
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



def test_export_bundle_preserves_provenance_and_is_digest_verifiable(tmp_path: Path):
    import hashlib
    import json

    (tmp_path / "app.py").write_text("print('ok')\\n", encoding="utf-8")
    service = ProductService(
        Settings(database_url=f"sqlite:///{tmp_path / 'export.db'}", object_store_path=str(tmp_path / "objects"))
    )
    project = service.create_project("export-fixture", str(tmp_path))
    result = service.analyze_sync(project.id, tmp_path)
    analysis_id = result["analysis"]["id"]
    bundle = service.export_bundle(analysis_id)

    assert bundle["bundle_version"] == "1.0"
    assert bundle["analysis"]["id"] == analysis_id
    assert bundle["snapshot"]["id"] == result["snapshot"]["id"]
    assert bundle["producer"]["name"] == "fas"
    assert bundle["evidence"]
    assert "graph" in bundle and set(bundle["graph"]) == {"nodes", "edges"}
    digest = bundle.pop("bundle_sha256")
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert digest == hashlib.sha256(canonical).hexdigest()


def test_export_bundle_rejects_snapshot_from_another_analysis(tmp_path: Path):
    (tmp_path / "app.py").write_text("print('ok')\\n", encoding="utf-8")
    service = ProductService(
        Settings(database_url=f"sqlite:///{tmp_path / 'scope.db'}", object_store_path=str(tmp_path / "objects"))
    )
    project = service.create_project("scope-fixture", str(tmp_path))
    first = service.analyze_sync(project.id, tmp_path)
    second = service.analyze_sync(project.id, tmp_path)
    try:
        service.export_bundle(first["analysis"]["id"], second["snapshot"]["id"])
    except ValueError as exc:
        assert "does not belong" in str(exc)
    else:
        raise AssertionError("cross-analysis snapshot export must be rejected")
