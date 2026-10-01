-- Phase 10 durable integration idempotency.
CREATE TABLE IF NOT EXISTS fas_integration_events (
  tenant_id text NOT NULL,
  fingerprint text NOT NULL,
  event_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, fingerprint)
);
