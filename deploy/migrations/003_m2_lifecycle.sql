-- deploy/migrations/003_m2_lifecycle.sql — M2 rule lifecycle (R11/R17 rulings).
-- The grant matrix IS the design: content columns of `rules` are UPDATE-denied
-- for every role; the only mutable cell in the event store is
-- normalized_events.superseded_by_event_id, held by onboarding_role.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='rules_role') THEN
    CREATE ROLE rules_role LOGIN PASSWORD 'rules_dev'; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='onboarding_role') THEN
    CREATE ROLE onboarding_role LOGIN PASSWORD 'onboarding_dev'; END IF;
END $$;

ALTER TABLE rules ADD CONSTRAINT rules_version_pos CHECK (version >= 1);
ALTER TABLE rules ADD COLUMN validation JSONB;  -- written once at candidate creation
CREATE UNIQUE INDEX rules_one_pending ON rules (fingerprint_id) WHERE status = 'pending_review';

-- Sample split becomes durable, auditable evidence (anti-leakage fix, spec §6.2).
ALTER TABLE onboarding_samples
  ADD CONSTRAINT onboarding_samples_role_chk CHECK (role IN ('prompt','held_out','unused'));
-- Replay idempotency for sample capture: one raw line -> at most one sample.
CREATE UNIQUE INDEX onboarding_samples_raw_id ON onboarding_samples (raw_id);

-- Reparse-sweep query support (find current rows older than the active version).
CREATE INDEX ne_current_fp_idx ON normalized_events (fingerprint_id)
  INCLUDE (rule_version) WHERE superseded_by_event_id IS NULL;

-- Generation-attempt bookkeeping (operational state, not event data).
CREATE TABLE onboarding_attempts (
  fingerprint_id TEXT PRIMARY KEY,
  samples_seen   INT NOT NULL,
  attempted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  error          TEXT
);

-- gateway write path (approve/reject/manual/deactivate/reactivate)
GRANT SELECT, INSERT ON rules TO rules_role;
GRANT UPDATE (status, activated_at, deactivated_at) ON rules TO rules_role;
GRANT INSERT ON audit_log TO rules_role;
GRANT SELECT ON onboarding_samples TO rules_role;

-- onboarding service (candidate generation + backlog re-parse, R11)
GRANT SELECT, INSERT ON rules TO onboarding_role;
GRANT INSERT ON audit_log TO onboarding_role;
GRANT SELECT, UPDATE (role) ON onboarding_samples TO onboarding_role;
GRANT SELECT ON raw_events TO onboarding_role;
GRANT INSERT, SELECT, UPDATE (superseded_by_event_id) ON normalized_events TO onboarding_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON onboarding_attempts TO onboarding_role;

-- T5 carry-forward: gateway should not read migration metadata, and future
-- tables (M3 drift_windows/baseline_profiles) must inherit gateway SELECT.
REVOKE SELECT ON schema_migrations FROM gateway_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO gateway_role;
