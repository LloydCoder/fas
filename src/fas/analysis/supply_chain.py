"""Bounded SBOM normalization for software supply-chain analysis."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
@dataclass(frozen=True, slots=True)
class PackageComponent:
    bom_ref: str
    name: str
    version: str
    purl: str | None = None
    hashes: tuple[str, ...] = ()

@dataclass(frozen=True, slots=True)
class DependencyRelation:
    source: str
    target: str

@dataclass(frozen=True, slots=True)
class SupplyChainInventory:
    spec_version: str
    components: tuple[PackageComponent, ...]
    dependencies: tuple[DependencyRelation, ...]

class CycloneDXInventoryParser:
    """Parse a bounded CycloneDX JSON inventory without executing package data."""

    def __init__(self, *, max_components: int = 50_000, max_dependencies: int = 100_000) -> None:
        if max_components < 1 or max_dependencies < 1:
            raise ValueError("limits must be positive")
        self.max_components, self.max_dependencies = max_components, max_dependencies

    def parse(self, document: dict[str, Any]) -> SupplyChainInventory:
        if document.get("bomFormat") != "CycloneDX":
            raise ValueError("unsupported BOM format")
        version = str(document.get("specVersion", ""))
        if not version:
            raise ValueError("CycloneDX specVersion is required")
        raw_components = document.get("components", [])
        raw_dependencies = document.get("dependencies", [])
        if not isinstance(raw_components, list) or not isinstance(raw_dependencies, list):
            raise ValueError("components and dependencies must be arrays")
        if len(raw_components) > self.max_components or len(raw_dependencies) > self.max_dependencies:
            raise ValueError("CycloneDX inventory exceeds configured limits")
        components: list[PackageComponent] = []
        for item in raw_components:
            if not isinstance(item, dict):
                raise ValueError("component entries must be objects")
            ref, name, version_value = item.get("bom-ref"), item.get("name"), item.get("version")
            if not all(isinstance(v, str) and v for v in (ref, name, version_value)):
                raise ValueError("component requires bom-ref, name, and version")
            hashes = tuple(sorted(str(h.get("content")) for h in item.get("hashes", [])
                                  if isinstance(h, dict) and h.get("content")))
            components.append(PackageComponent(ref, name, version_value, item.get("purl"), hashes))
        relations: list[DependencyRelation] = []
        for item in raw_dependencies:
            if not isinstance(item, dict) or not isinstance(item.get("ref"), str):
                raise ValueError("dependency requires ref")
            for target in item.get("dependsOn", []):
                if not isinstance(target, str):
                    raise ValueError("dependency targets must be strings")
                relations.append(DependencyRelation(item["ref"], target))
        return SupplyChainInventory(version, tuple(sorted(components, key=lambda x: x.bom_ref)),
                                    tuple(sorted(relations, key=lambda x: (x.source, x.target))))
