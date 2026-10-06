# Schemas and contracts

Machine-readable contracts live under [schemas/](../../schemas/).

When a schema changes:

1. update the schema;
2. update affected producers and consumers;
3. run <code>python scripts/check_schema_parity.py</code>;
4. add regression coverage;
5. update reference documentation;
6. update the changelog when user-visible.

Do not infer a public contract from a single implementation module when a canonical schema exists.
