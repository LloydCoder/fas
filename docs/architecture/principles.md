# Architecture Principles

## 1. Evidence is the security substrate

Security conclusions are downstream of evidence. Components that cannot establish evidence should not silently manufacture it.

## 2. Analysis state is immutable

An analysis is tied to a snapshot. Later observations create new records rather than rewriting historical evidence.

## 3. Provenance travels with relationships

Graph edges are security-relevant facts. Important edges therefore carry provenance and evidence references.

## 4. Models propose; deterministic systems establish

LLMs can form hypotheses, select investigation paths, and propose conclusions. Evidence acquisition and verification remain constrained by deterministic interfaces.

## 5. Missing evidence is explicit

The system must represent missing evidence rather than filling gaps with assumptions.

## 6. Remediation is a verification problem

A patch is evaluated against the original attack path and the resulting graph. The system checks for residual and alternate paths.

## 7. Security boundaries are explicit

Untrusted repositories, tool output, runtime targets, and model-provided content must be treated according to their trust level.

## 8. Start simple

FAS begins as a modular monolith with worker isolation. Distributed components are introduced only when scale or isolation requirements justify them.
