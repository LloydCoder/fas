#!/usr/bin/env python3
"""Fail-closed FAS verification against the canonical TSIC evidence-analysis adapter."""

from __future__ import annotations

import base64
import json
from urllib.request import Request, urlopen

TSIC_REVISION = "1740ad6be773dbbd8005d263cff5b553fa684ac3"
REQUIRED = {
    "identity-context",
    "event-envelope",
    "delivery-semantics",
    "trace-context",
    "economic-attribution",
}


def fetch_json(path: str) -> dict:
    url = f"https://api.github.com/repos/LloydCoder/tinlance-system-integration/contents/{path}?ref={TSIC_REVISION}"
    request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "tinlance-fas-tsic"})
    with urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError(f"TSIC contents API returned HTTP {response.status}: {url}")
        payload = json.load(response)
    return json.loads(base64.b64decode(payload["content"].replace("\n", "")).decode("utf-8"))


def main() -> None:
    manifest = fetch_json("manifests/ecosystem.json")
    adapter = fetch_json("integrations/fas/adapter.json")
    registry = fetch_json("catalog/contracts/registry.json")

    system = next(item for item in manifest["systems"] if item["id"] == "fas")
    assert system["repository"] == "LloydCoder/fas"
    assert system["governance_role"] == "forensic_analysis_authority"

    assert adapter["source_system"] == "tsic"
    assert adapter["target_system"] == "fas"
    assert adapter["status"] == "reference-contract"
    assert {item["tsic_contract"] for item in adapter["contract_bindings"]} == REQUIRED
    assert {item["id"] for item in registry["contracts"]} >= REQUIRED
    assert adapter["authority"]["integration_contracts"] == "tsic"
    assert adapter["authority"]["evidence_analysis"] == "fas"
    assert adapter["authority"]["execution_authority"] == "agent-platform"

    required_invariants = {
        "observation_is_not_evidence",
        "evidence_is_not_finding",
        "finding_is_not_verdict",
        "provenance_is_preserved",
        "analysis_does_not_grant_execution_authority",
        "tsic_remains_integration_authority",
        "agent-platform-remains-execution-authority",
    }
    assert set(adapter["invariants"]) == required_invariants

    print(f"PASS TSIC-30 FAS conformance: revision={TSIC_REVISION}")


if __name__ == "__main__":
    main()
