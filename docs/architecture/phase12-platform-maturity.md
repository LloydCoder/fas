# FAS Phase 12 — Governed Autonomous Security Research

Phase 12 is the terminal numbered maturity phase. It adds a bounded research scheduler rather than granting an autonomous component security authority.

## Research loop

1. A bounded research run receives a snapshot scope and budget.
2. Hypotheses are represented explicitly.
3. The scheduler proposes evidence requests.
4. Requests requiring approval remain pending until an authorized policy or human workflow approves them.
5. Collectors and verification systems remain responsible for producing evidence and conclusions.
6. The research run records completion and stopping reasons.
7. Autonomous output cannot be marked authoritative.

## Hard boundaries

- no autonomous evidence fabrication
- no autonomous verdict creation
- no bypass of snapshot scope
- no unbounded request generation
- no implicit approval
- no hidden escalation of execution capability

This design allows future model-assisted investigators to operate inside an existing evidence-first authority substrate instead of becoming a second source of truth.
