# Phase 15 Threat Model — Analyzer SDK

| Threat | Control |
|---|---|
| Extension duplicates or shadows another analyzer | Registry rejects duplicate names |
| Analyzer output is mistaken for authoritative evidence | Contract returns observations only |
| Extension gains execution authority | SDK accepts CollectionContext but owns no executor |
| Non-deterministic registry output | Names are canonically sorted |

Residual risk: third-party analyzers remain untrusted code and must be isolated by the caller's execution boundary.
