# FAS canonical JSON schemas

The Phase 1 Pydantic v2 models under `src/fas/domain/` are the authoritative
implementation contracts. The checked-in JSON documents are the interoperable
wire/schema artifacts and carry `x-fas-canonical-model` plus
`x-fas-schema-version` metadata.

The schema-contract tests verify that required model fields and critical enum
taxonomies cannot silently disappear from the checked-in schemas.

The legacy `analysis-result.schema.json` remains for compatibility with the
initial repository contract; new Phase 1 code must use the canonical domain
models and the schemas named after those models.
