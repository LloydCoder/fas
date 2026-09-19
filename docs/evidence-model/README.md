# Evidence Model

Evidence is a first-class FAS domain object.

Every material security claim should be traceable through:

```
Verdict -> Finding -> Attack Path -> Graph Edge -> Evidence -> Artifact -> Snapshot
```

Evidence should preserve:

- source artifact and location
- observed value
- collection method
- tool/collector identity and version
- analysis/snapshot association
- integrity information
- observation time

An observation is not automatically a finding, and a model inference is not automatically evidence.

Canonical JSON schemas will be added as the domain model is implemented.
