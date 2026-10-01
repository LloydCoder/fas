-- Phase 7 base hosted persistence migration.
-- The PostgreSQL adapter may also create these idempotently during first startup.
CREATE TABLE IF NOT EXISTS fas_tenants (
  tenant_id text PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fas_memberships (
  tenant_id text NOT NULL REFERENCES fas_tenants(tenant_id),
  subject text NOT NULL,
  role text NOT NULL CHECK (role IN ('reader','analyst','admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, subject)
);
