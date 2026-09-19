# FAS Phase 6 Productization Architecture

Phase 6 turns the existing evidence, graph, collection, investigation, and verification engines into a bounded product interface without moving security semantics into transport code.

## Runtime boundary

```text
CLI / HTTP API
      |
      v
ProductService
      |
  +---+---+
  |       |
SQLite  Object Store
  |
jobs/audit/domain records
      |
collection / normalization / graph / investigation / verification engines
      |
evidence graph
```

The supported local deployment uses SQLite and a content-addressed local object store. The persistence and object-store interfaces are intentionally small so PostgreSQL and S3-compatible implementations can be added without changing domain semantics.

## API

The public API namespace is `/v1`. The API validates requests, enforces the local/non-local authentication boundary, emits stable structured errors, and delegates domain operations to ProductService.

The API never executes arbitrary repository commands from HTTP input and never allows transport-level code to create authoritative security evidence. Non-local binding requires authentication; request bodies and JSON structure are bounded; malformed input is converted to stable errors.

## CLI

The `fas` executable uses the same ProductService as the HTTP API. Human output is presentation only; `--format json` is the machine-readable contract.

## Jobs

The local worker uses bounded ThreadPoolExecutor concurrency with durable SQLite job state, operation-key idempotency, cancellation events, worker/lease metadata, and crash recovery of jobs left in RUNNING state.

## Artifact handling

Large or reusable byte content is stored by SHA-256 content address through LocalObjectStore. Writes use unique temporary files, flush/fsync and atomic replacement; reads rehash content and reject corruption.

## Security boundary

Analyzed repositories are hostile inputs. The product layer uses explicit sandbox policy types and safe environment/argv primitives. The current product profile does not execute arbitrary candidate repository code. Unsupported runtime execution is reported as unsupported rather than simulated.

## Capability boundaries

The local product profile intentionally does not claim PostgreSQL production scaling, cloud object storage availability, arbitrary repository runtime execution, universal scanner coverage, or formal SLSA/NIST/OWASP compliance.

## API/CLI/domain separation

The domain and core analysis engines do not import the HTTP server or CLI. Product adapters depend on domain contracts, not the reverse. Reporting projects persisted state; it does not recalculate security conclusions.

## FAS-Bench

FAS-Bench is external. The product layer exposes stable JSON projections suitable for evaluation without making the benchmark a runtime dependency.

## Completeness and evidence boundary

Snapshot manifests record bounded omissions and completeness. Collection failures, parser failures, output truncation, and bounded discovery are propagated as PARTIAL/UNKNOWN conditions rather than converted into clean conclusions. Reports expose completeness explicitly and do not authorize a clean claim from partial analysis.
