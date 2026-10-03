# Phase 16 Threat Model — Supply-Chain Inventory

| Threat | Control |
|---|---|
| Maliciously oversized SBOM | Component/dependency limits |
| Unexpected JSON shape | Strict object/array validation |
| Dependency relationship ambiguity | Canonically sorted source/target pairs |
| Inventory mistaken for vulnerability evidence | Parser produces inventory only |
| Package content executed during parsing | Parser performs no execution |

Residual risk: package identifiers and advisory semantics still require trusted upstream sources and evidence provenance.
