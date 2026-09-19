import json
import subprocess
import sys
from pathlib import Path


def test_cli_analyze_status_and_report_e2e(tmp_path: Path) -> None:
    source = tmp_path / "fixture"
    source.mkdir()
    (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "database_url": f"sqlite:///{tmp_path / 'fas.db'}",
                "object_store_path": str(tmp_path / "objects"),
            }
        ),
        encoding="utf-8",
    )

    analyze = subprocess.run(
        [sys.executable, "-m", "fas.cli", "--config", str(config), "--format", "json", "analyze", str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert analyze.returncode == 2
    payload = json.loads(analyze.stdout)
    analysis_id = payload["analysis"]["id"]
    assert payload["analysis"]["status"] == "PARTIAL"

    status = subprocess.run(
        [sys.executable, "-m", "fas.cli", "--config", str(config), "--format", "json", "status", analysis_id],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(status.stdout)["id"] == analysis_id

    report = subprocess.run(
        [sys.executable, "-m", "fas.cli", "--config", str(config), "--format", "json", "report", analysis_id],
        capture_output=True,
        text=True,
        check=False,
    )
    assert report.returncode == 2
    report_payload = json.loads(report.stdout)
    assert report_payload["content"]["executive_summary"]["clean_claim_permitted"] is False
