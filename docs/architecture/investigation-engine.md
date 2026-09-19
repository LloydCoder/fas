# Phase 4 Investigation Engine

Phase 4 converts a candidate finding into a bounded, evidence-grounded investigation.

`Finding -> Case -> Hypothesis -> Evidence Request -> Deterministic Primitive -> Graph Expansion -> Attack Path -> Control/Permission Analysis -> Exploitability Analysis -> Verdict Proposal`

Every investigation is bound to exactly one analysis and immutable snapshot. Deterministic tools operate through `DeterministicInvestigator`; the model layer can propose hypotheses and requests but cannot create evidence or authorize execution.

A graph path is only a structural candidate. `validate_attack_path` requires every security transition to carry evidence and preserves snapshot scope. Missing or contradictory evidence prevents a definitive exploitability proposal.


CI acceptance is performed by the repository workflow before Phase 4 is declared complete.
