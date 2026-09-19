-- deploy/migrations/001_init.sql — spec §4. Owner is the migration user; app roles get least privilege.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='pipeline_role') THEN
    CREATE ROLE pipeline_role LOGIN PASSWORD 'pipeline_dev'; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='gateway_role') THEN
    CREATE ROLE gateway_role LOGIN PASSWORD 'gateway_dev'; END IF;
END $$;

CREATE TABLE raw_events (
  raw_id        UUID NOT NULL,
  received_at   TIMESTAMPTZ NOT NULL,
  source_id     TEXT NOT NULL,
  transport     TEXT NOT NULL,
  format_hint   TEXT,
  fingerprint_id TEXT,
  content_hash  TEXT NOT NULL,
  raw_text      TEXT NOT NULL,
  PRIMARY KEY (raw_id, received_at)
) PARTITION BY RANGE (received_at);

CREATE TABLE raw_batches (
  partition_id INT  NOT NULL,          -- kafka partition
  batch_seq    BIGINT NOT NULL,
  prev_hash    TEXT NOT NULL,          -- previous batch's merkle_root; 64 zeros for genesis
  merkle_root  TEXT NOT NULL,
  row_hashes   JSONB NOT NULL,         -- ordered content hashes of the batch (verifier input)
  count        INT  NOT NULL,
  first_offset BIGINT NOT NULL,
  last_offset  BIGINT NOT NULL,
  written_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (partition_id, batch_seq)
);

CREATE TABLE normalized_events (
  event_id     UUID NOT NULL,
  raw_id       UUID NOT NULL,
  raw_received_at TIMESTAMPTZ NOT NULL,
  parsed_at    TIMESTAMPTZ NOT NULL,   -- set to raw received_at (deterministic; spec §4 note)
  fingerprint_id TEXT NOT NULL,
  rule_id      INT,
  rule_version INT,
  status       TEXT NOT NULL CHECK (status IN ('parsed','unparsed','quarantined','parse_error')),
  ocsf         JSONB,
  superseded_by_event_id UUID,
  PRIMARY KEY (event_id, parsed_at),
  FOREIGN KEY (raw_id, raw_received_at) REFERENCES raw_events (raw_id, received_at)
) PARTITION BY RANGE (parsed_at);
CREATE INDEX ne_current_idx ON normalized_events (parsed_at DESC) WHERE superseded_by_event_id IS NULL;
CREATE INDEX ne_fp_idx ON normalized_events (fingerprint_id, parsed_at);

CREATE TABLE rules (
  id SERIAL PRIMARY KEY,
  fingerprint_id TEXT NOT NULL,
  version INT NOT NULL,
  pattern TEXT NOT NULL,
  mappings JSONB NOT NULL,
  provenance TEXT NOT NULL CHECK (provenance IN ('slm','slm-edited','human')),
  confidence REAL,
  status TEXT NOT NULL DEFAULT 'pending_review'
    CHECK (status IN ('pending_review','active','superseded','deactivated','rejected')),
  quarantined_fields TEXT[] NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  activated_at TIMESTAMPTZ,
  deactivated_at TIMESTAMPTZ,
  UNIQUE (fingerprint_id, version)
);
CREATE UNIQUE INDEX rules_one_active ON rules (fingerprint_id) WHERE status = 'active';

CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor TEXT NOT NULL, action TEXT NOT NULL, entity TEXT NOT NULL, detail JSONB
);
CREATE TABLE onboarding_samples (
  id BIGSERIAL PRIMARY KEY, fingerprint_id TEXT NOT NULL, raw_id UUID NOT NULL,
  raw_text TEXT NOT NULL, captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  role TEXT NOT NULL DEFAULT 'unused'
);

GRANT INSERT, SELECT ON raw_events, raw_batches, normalized_events, onboarding_samples TO pipeline_role;
GRANT SELECT ON rules TO pipeline_role;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO gateway_role;
