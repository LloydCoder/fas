# Verification Evidence

Verification evidence is append-only and separate from original collection evidence.

A verification claim references one or more of:

- original/candidate evidence IDs
- artifacts and content hashes
- semantic graph diff
- attack-path comparison
- controlled security-test result
- configuration or permission evidence

Every verification result records supporting evidence, contradicting evidence, missing evidence,
limitations, snapshot IDs, and the verification plan.

A claim such as "the original path is no longer reachable" is valid only when the corresponding
candidate graph was complete, snapshot-bound, and the bounded path analysis produced the result.
Missing evidence is not negative evidence.
