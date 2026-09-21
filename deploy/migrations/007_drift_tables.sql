-- deploy/migrations/007_drift_tables.sql — M3 drift detection (R-M3-2/3).
-- Natural PKs ONLY (no serials): the 004/005/006 sequence-grant bug class is
-- structurally impossible here. Drift writes are INSERT-only.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='drift_role') THEN
    CREATE ROLE drift_role LOGIN PASSWORD 'drift_dev'; END IF;
END $$;

CREATE TABLE drift_windows (
  fingerprint_id TEXT NOT NULL,
  rule_version   INT NOT NULL,
  field          TEXT NOT NULL,        -- OCSF path, 'unmapped.<key>', or '__rule__' sentinel
  window_start   TIMESTAMPTZ NOT NULL, -- parsed_at of the window's first event (deterministic key)
  window_end     TIMESTAMPTZ NOT NULL,
  events_count   INT NOT NULL,
  null_rate      REAL,
  match_rate     REAL,                 -- '__rule__' rows: parsed / (parsed + parse_error)
  violation_rate REAL,                 -- tier-1 invariant violations for this field
  shape_dist     JSONB,                -- {"ipv4": 12, "int": 3, ...} over non-null scalar values
  severity       TEXT NOT NULL CHECK (severity IN ('none','minor','moderate','severe')),
  action_taken   TEXT CHECK (action_taken IS NULL OR action_taken IN
                ('alert','field_quarantined','rule_deactivated')),
  scanned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (fingerprint_id, rule_version, field, window_start)
);
CREATE INDEX drift_windows_recent ON drift_windows (fingerprint_id, window_start DESC);

CREATE TABLE baseline_profiles (
  fingerprint_id TEXT NOT NULL,
  rule_version   INT NOT NULL,
  field          TEXT NOT NULL,
  profile        JSONB NOT NULL,       -- {events_count, null_rate, match_rate, shape_dist}
  windows_seen   INT NOT NULL,
  established_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (fingerprint_id, rule_version, field)
);

-- drift service (detection + enforcement, R-M3-3)
GRANT SELECT ON normalized_events, rules TO drift_role;
GRANT INSERT ON drift_windows, baseline_profiles TO drift_role;
-- P-2: drift_role self-reads — baseline existence checks + recent-window lookups.
GRANT SELECT ON drift_windows, baseline_profiles TO drift_role;
GRANT UPDATE (quarantined_fields) ON rules TO drift_role;
GRANT UPDATE (status, deactivated_at) ON rules TO drift_role;
GRANT INSERT ON audit_log TO drift_role;
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO drift_role;

-- gateway: human override of quarantine (audited, rules_role write path)
GRANT UPDATE (quarantined_fields) ON rules TO rules_role;
-- gateway SELECT on both new tables arrives via 003's ALTER DEFAULT PRIVILEGES.
