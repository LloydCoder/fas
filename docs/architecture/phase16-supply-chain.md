# Phase 16 — Software Supply-Chain Inventory

Phase 16 adds a bounded CycloneDX JSON inventory parser. The current CycloneDX specification is
1.7. The parser preserves component identity, PURLs, hashes, and dependency relationships while
remaining read-only and bounded.

This is inventory normalization, not vulnerability truth. FAS does not infer exploitability from
a package name or version alone. Vulnerability/advisory evidence remains attributable to its source.
