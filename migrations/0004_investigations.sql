-- Phase 4 persistence contract. The current repository has no live database adapter;
-- these tables define the PostgreSQL system-of-record seam for production integration.
CREATE TABLE IF NOT EXISTS investigations (
  investigation_id text PRIMARY KEY,
  analysis_id text NOT NULL,
  finding_id text NOT NULL,
  snapshot_id text NOT NULL,
  status text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_investigations_snapshot ON investigations(analysis_id,snapshot_id);
CREATE TABLE IF NOT EXISTS investigation_events (
  event_id text PRIMARY KEY,
  investigation_id text NOT NULL REFERENCES investigations(investigation_id),
  analysis_id text NOT NULL,
  snapshot_id text NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_investigation_events_scope ON investigation_events(investigation_id,created_at);
CREATE TABLE IF NOT EXISTS investigation_results (
  investigation_id text PRIMARY KEY REFERENCES investigations(investigation_id),
  analysis_id text NOT NULL,
  snapshot_id text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL
);
