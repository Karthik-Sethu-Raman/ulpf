-- deploy/migrations/004_sample_capture_grants.sql — pipeline sample capture
-- (R17, Task 4) inserts into onboarding_samples, whose BIGSERIAL id needs
-- sequence USAGE; migration 001 granted the TABLE only, which stayed latent
-- until the first sample insert ran (caught by the Task 4 live check).
GRANT USAGE, SELECT ON SEQUENCE onboarding_samples_id_seq TO pipeline_role;
