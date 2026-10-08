# TSIC integration

FAS is Tinlance's evidence-first forensic analysis layer.

- **TSIC** owns ecosystem integration and certification.
- **FAS** owns forensic/evidence-analysis semantics.
- **Agent Platform** owns governed consequential execution.

The evidence chain is deliberately non-collapsing:

`observation → evidence → finding → verdict`

An observation is not evidence; evidence is not a finding; a finding is not a verdict. Provenance must survive every boundary. FAS cannot grant execution authority.

## Conformance

`scripts/tsic_conformance.py` consumes the immutable TSIC-30 adapter revision and verifies identity, event, delivery, trace and economic-attribution contracts plus the evidence/provenance authority invariants.

Run:

```bash
python scripts/tsic_conformance.py
```

Passing the gate certifies the reviewed integration contract, not a production forensic engagement.
