# Phase 5 Verification Threat Model

| Threat | Asset | Precondition | Impact | Mitigation | Verification test | Residual risk |
|---|---|---|---|---|---|---|
| Malicious patch | candidate snapshot | attacker controls candidate source | false remediation | candidate treated as untrusted; no arbitrary execution | prompt-injection fixture | malicious behavior outside observed scope |
| Snapshot substitution | snapshot identity | attacker changes artifact/reference | false comparison | explicit snapshot IDs, scope checks, hashes where available | mismatch fixture | unavailable external artifact |
| Evidence substitution | verification evidence | attacker alters evidence reference | false result | append-only references and provenance | immutable-history test | storage compromise |
| Graph poisoning | graph | hostile collector output | false path result | provenance-backed nodes/edges and validation | hostile graph fixture | incomplete collector coverage |
| Test manipulation | security-test definition/result | untrusted test metadata | false success | structured test definitions and controlled executor | failing-test fixture | future sandbox implementation |
| Tool-version confusion | scanner drift | versions differ | incomparable observations | capture tool/adapter versions and limitations | version-drift test | semantic drift not fully modeled |
| Baseline tampering | regression baseline | attacker modifies prior result | missed regression | immutable baseline model and append-only history | baseline mutation test | backend enforcement |
| LLM manipulation | candidate content/prompt injection | model sees repository text | fabricated conclusion | LLM is advisory; deterministic evidence wins | investigator boundary tests | model-specific prompt attacks |
| Verification bypass | workflow | caller skips required checks | false REMEDIATED | result invariants and completeness gate | no-false-success tests | integration caller bugs |
| Resource exhaustion | huge graph/path set | hostile repository | denial of service | bounded traversal/path limits | bounded search tests | host-level limits |
