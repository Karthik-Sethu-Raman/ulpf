-- deploy/migrations/006_rules_sequence_grants.sql — rules_role and
-- onboarding_role INSERT into rules, whose BIGSERIAL id needs sequence USAGE;
-- migration 003 granted the TABLE only, which stayed latent until the first
-- live candidate insert ran (caught by the Task 12 smoke: F's manual
-- fallback POST /api/rules/manual failed with "permission denied for
-- sequence rules_id_seq" — the same bug class 004 fixed for
-- pipeline_role/onboarding_samples_id_seq and 005 for the audit sequence).
-- rules_role needs it for manual candidates; onboarding_role for SLM
-- candidates (migration 003 grants both roles INSERT ON rules).
GRANT USAGE, SELECT ON SEQUENCE rules_id_seq TO rules_role;
GRANT USAGE, SELECT ON SEQUENCE rules_id_seq TO onboarding_role;
