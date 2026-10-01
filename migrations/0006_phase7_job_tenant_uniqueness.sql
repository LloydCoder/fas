-- Phase 7 job isolation correction: idempotency keys are unique within a tenant.
-- New PostgreSQL deployments create this invariant in the adapter; this migration is
-- provided for deployments that already created the Phase 7 job table.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='fas_jobs'::regclass AND conname='fas_jobs_operation_key_key'
  ) THEN
    ALTER TABLE fas_jobs DROP CONSTRAINT fas_jobs_operation_key_key;
  END IF;
EXCEPTION WHEN undefined_table THEN
  NULL;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS uq_fas_jobs_tenant_operation ON fas_jobs(tenant_id, operation_key);
