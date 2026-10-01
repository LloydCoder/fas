# Phase 9 runtime threats

The runtime adapter crosses the highest-risk FAS trust boundary.

Required invariants:
1. No runtime execution without explicit executable allowlisting.
2. No ambient environment inheritance.
3. No network access in the supported Phase 9 profile.
4. No secret injection.
5. Filesystem visibility is explicitly constructed by the executor.
6. CPU, memory, process, file-size, file-count and output limits remain active.
7. Timeout and cancellation terminate the complete process group.
8. Unsupported runtime policies fail closed.
9. Runtime observations remain scoped to the candidate snapshot.
10. A runtime result cannot directly create a verdict.
