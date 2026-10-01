# Phase 8 analysis threats

Advanced analysis is itself security-sensitive because graph traversal can amplify incomplete or hostile input.

Required invariants:
1. Analysis never crosses analysis or snapshot scope.
2. Traversal is bounded by graph and analyzer limits.
3. TRUNCATED/PARTIAL results are preserved.
4. Evidence IDs are inherited only from actual path nodes and edges.
5. Analysis signals cannot become findings or verdicts automatically.
6. Malformed graph state fails closed through existing graph validation.
