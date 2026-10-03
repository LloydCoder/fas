# Phase 14 Threat Model — Evidence Correlation

| Threat | Control |
|---|---|
| Duplicate-looking evidence is treated as proof of multiple independent sources | Correlation groups preserve every original evidence ID |
| Fingerprints vary between runs | Canonical JSON and stable hashing |
| Timezone ambiguity changes temporal results | Timezone-aware validation |
| Temporal filters silently omit records | Results carry explicit completeness |
| Correlation becomes a verdict engine | Module has no finding/verdict mutation or authority |

Residual risk: semantic equivalence cannot be proven by a fingerprint alone; consumers must retain provenance and source distinctions.
