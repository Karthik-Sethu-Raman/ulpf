"""services/drift/tests/test_migration_007_pin.py — pins the FILE
deploy/migrations/007_drift_tables.sql, not service behavior (the M1
migration-pin style: the SQL file is the contract, so any edit to its grants
or keys must consciously update this test too).

Pinned, per R-M3-3's "the grant matrix is the design": (a) both column-level
GRANT UPDATE (quarantined_fields) lines — drift enforcement and the gateway's
human override; (b) natural composite PKs on both tables (R-M3-2's
INSERT-only, ON CONFLICT DO NOTHING idempotence); (c) no SERIAL-family token
anywhere in the SQL — the 004/005/006 sequence-grant bug class stays
structurally impossible, the one allowed serial context being the audit_log
sequence grant line (pinned verbatim below).
"""

import re
from pathlib import Path

# Repo root regardless of CWD: tests/ -> drift/ -> services/ -> root.
MIGRATION = (
    Path(__file__).resolve().parents[3] / "deploy" / "migrations" / "007_drift_tables.sql"
)

# The only sequence context drift legitimately touches: audit_log's serial id
# backing sequence, granted to drift_role.
AUDIT_SEQUENCE_GRANT = "GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO drift_role;"


def test_migration_007_grants_keys_and_no_serials_pinned():
    """One pin over the whole file (a)/(b)/(c):

    (a) both column-level UPDATE grants on rules.quarantined_fields exist
        verbatim — drift_role enforces (R-M3-3), rules_role is the gateway's
        un-quarantine write path; losing either surfaces as a live
        permissions error, not a test failure;
    (b) both CREATE TABLE statements key on natural composite PKs derived
        from data (R-M3-2) — a surrogate key would need a sequence grant and
        break ON CONFLICT DO NOTHING re-scan idempotence;
    (c) a case-insensitive serial grep over the file's SQL stays empty —
        comment prose is not SQL (the header's '(no serials)' is stripped
        before matching), and any surviving SERIAL/SMALLSERIAL/BIGSERIAL
        token fails unless it sits on the pinned audit_log sequence grant
        line, the 004/005/006 bug class locked out by construction.
    """
    sql = MIGRATION.read_text(encoding="utf-8")

    # (a) the grant matrix
    assert "GRANT UPDATE (quarantined_fields) ON rules TO drift_role;" in sql
    assert "GRANT UPDATE (quarantined_fields) ON rules TO rules_role;" in sql

    # (b) natural composite PKs, verbatim clauses
    assert "PRIMARY KEY (fingerprint_id, rule_version, field, window_start)" in sql
    assert "PRIMARY KEY (fingerprint_id, rule_version, field)" in sql

    # (c) no serial tokens in SQL outside the audit sequence grant line
    code = "\n".join(line.split("--", 1)[0] for line in sql.splitlines())
    offenders = [
        line.strip()
        for line in code.splitlines()
        if re.search(r"(?i)serial", line) and line.strip() != AUDIT_SEQUENCE_GRANT
    ]
    assert offenders == []
