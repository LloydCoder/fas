# Phase 6 Evidence and Product Contract

Phase 6 does not introduce a second evidence model.

The authoritative chain remains:

verdict -> finding -> attack path -> graph relationship -> evidence -> artifact -> snapshot

Evidence is immutable and snapshot-bound. Product records may index or project evidence, but the API, CLI, report generator, or LLM investigator cannot rewrite historical evidence.

Negative evidence is explicit. A missing observation, an empty query, or a truncated search is not silently converted into proof of absence.

Content-addressed artifact storage uses SHA-256. Generated product artifacts retain producer/source metadata where the underlying domain contract supports it.

Provenance strength (T0–T5) and model confidence remain separate concepts.
