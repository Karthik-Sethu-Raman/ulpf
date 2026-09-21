-- deploy/migrations/005_audit_sequence_grants.sql — onboarding_role and
-- rules_role INSERT audit_log rows, whose BIGSERIAL id needs sequence USAGE;
-- migration 003 granted the TABLE only, which stayed latent until the first
-- live audit write ran (caught by the Task 11 live verify: the onboarding
-- loop failed with "permission denied for sequence audit_log_id_seq" — the
-- same bug class 004 fixed for pipeline_role/onboarding_samples_id_seq).
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO onboarding_role;
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO rules_role;
