# services/onboarding/tests/test_store.py — store SQL pinned through a
# recording fake conn/cursor (the M1 pipeline db-test style; NEVER a live DB).
#
# The fake records (sql, params) in execution order and brackets each
# `with conn.transaction():` block with TXN-START / TXN-COMMIT (or
# TXN-ROLLBACK) markers, so "version select -> rules INSERT -> audit INSERT,
# all inside one txn" is an assertion on the recorded sequence. Fetch results
# are consumed FIFO so one call can drive several queries. psycopg is not on
# the test path, so its Json wrapper is unwrapped duck-typed via .obj.
from ulpf_core.models import Mapping
from ulpf_core.validation import CandidateReport, report_to_json

from onboarding.config import Config
from onboarding.generate import GeneratedRule
from onboarding.store import (
    audit,
    count_samples,
    has_active_or_pending,
    insert_candidate,
    load_samples,
    mark_roles,
    ready_fingerprints,
    record_attempt,
)


class FakeConn:
    """Fake psycopg connection: records SQL, replays scripted fetch results."""

    def __init__(self, fetchone_results=(), fetchall_results=()):
        self.sql: list = []
        self.params: list = []
        self.txns_opened = 0
        self._fetchone = list(fetchone_results)
        self._fetchall = list(fetchall_results)

    def transaction(self):
        conn = self

        class Txn:
            def __enter__(self):
                conn.txns_opened += 1
                conn.sql.append("TXN-START")
                conn.params.append(None)  # keep sql/params index-aligned

            def __exit__(self, exc_type, exc, tb):
                conn.sql.append("TXN-ROLLBACK" if exc_type is not None else "TXN-COMMIT")
                conn.params.append(None)
                return False

        return Txn()

    def cursor(self):
        conn = self

        class Cur:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, sql, params=None):
                conn.sql.append(sql)
                conn.params.append(params)

            def fetchone(self):
                return list(conn._fetchone.pop(0)) if conn._fetchone else [1]

            def fetchall(self):
                return list(conn._fetchall.pop(0)) if conn._fetchall else []

        return Cur()


def _unwrap(value):
    """psycopg's Json adapter -> plain Python (duck-typed: no psycopg here)."""
    return value.obj if hasattr(value, "obj") else value


def _rule(confidence=0.93):
    return GeneratedRule(
        fingerprint_id="fp_a",
        version=1,
        pattern=r"^.*\|(?P<extension>.*)$",
        mappings=[Mapping(source_field="src", ocsf_path="src_endpoint.ip")],
        provenance="slm",
        confidence=confidence,
    )


def _report(passed=True):
    checks = {
        "caps_and_allowlist", "samples_parse", "held_out_match_all", "ip_fields_valid",
        "port_fields_valid", "no_orphan_mappings", "adversarial_probe",
        "no_hardcoded_literals",
    }
    return CandidateReport(
        passed=passed,
        checks={key: passed for key in checks},
        held_out_match_rate=1.0 if passed else 0.4,
        notes=["held-out line 3: boom"] if not passed else [],
        previews=[],
        prompt_count=5,
        held_out_count=15,
    )


# --- insert_candidate: pending_review row + version + validation + audit -----


def test_insert_candidate_pends_with_next_version_and_audits():
    conn = FakeConn(fetchone_results=[[1], [42]])  # version select, RETURNING id
    rule_id = insert_candidate(conn, _rule(), _report())

    assert rule_id == 42
    sql = [s for s in conn.sql if isinstance(s, str)]
    version_sql = next(s for s in sql if "COALESCE(MAX(version), 0) + 1" in s)
    insert_sql = next(s for s in sql if s.startswith("INSERT INTO rules"))
    audit_sql = next(s for s in sql if s.startswith("INSERT INTO audit_log"))
    # One txn: version select -> rules INSERT -> audit INSERT.
    assert conn.txns_opened == 1
    assert (sql.index("TXN-START") < sql.index(version_sql) < sql.index(insert_sql)
            < sql.index(audit_sql) < sql.index("TXN-COMMIT"))

    assert conn.params[sql.index(version_sql)] == ("fp_a",)
    assert "pending_review" in insert_sql and "validation" in insert_sql
    ip = [_unwrap(v) for v in conn.params[sql.index(insert_sql)]]
    # (fingerprint_id, version, pattern, mappings, provenance, confidence,
    #  created_by, validation)
    assert ip[0] == "fp_a" and ip[1] == 1
    assert ip[2] == r"^.*\|(?P<extension>.*)$"
    assert ip[3] == [{"source_field": "src", "ocsf_path": "src_endpoint.ip"}]
    assert ip[4] == "slm" and ip[5] == 0.93 and ip[6] == "onboarding"
    assert ip[7] == report_to_json(_report())

    assert conn.params[sql.index(audit_sql)][:3] == (
        "onboarding", "candidate_created", "fp_a")
    detail = _unwrap(conn.params[sql.index(audit_sql)][3])
    assert detail == {"rule_id": 42, "version": 1, "provenance": "slm",
                      "confidence": 0.93}


def test_insert_candidate_without_confidence_stores_null():
    from ulpf_core.models import Rule

    plain = Rule(
        fingerprint_id="fp_a", version=1, pattern="x",
        mappings=[Mapping(source_field="s", ocsf_path="message")], provenance="slm",
    )
    conn = FakeConn(fetchone_results=[[3], [7]])
    assert insert_candidate(conn, plain, _report()) == 7
    sql = [s for s in conn.sql if isinstance(s, str)]
    insert_sql = next(s for s in sql if s.startswith("INSERT INTO rules"))
    assert conn.params[sql.index(insert_sql)][5] is None


# --- ready_fingerprints: threshold + no active + no pending + retry gate -----


def test_ready_fingerprints_gates_on_threshold_rules_and_new_samples():
    conn = FakeConn(fetchall_results=[[("fp_a",), ("fp_b",)]])
    cfg = Config()
    fps = ready_fingerprints(conn, cfg)

    assert fps == ["fp_a", "fp_b"]
    sql = next(s for s in conn.sql if isinstance(s, str) and "onboarding_samples" in s)
    # TOTAL samples per fingerprint (any role) against the threshold.
    assert "count(*)" in sql and "GROUP BY fingerprint_id" in sql
    assert "s.total >= %s" in sql
    assert "status = 'active'" in sql and "status = 'pending_review'" in sql
    assert sql.count("NOT EXISTS") == 2
    # No attempt row yet, OR enough new samples since the last attempt.
    assert "a.fingerprint_id IS NULL OR s.total - a.samples_seen >= %s" in sql
    assert "JOIN onboarding_attempts" in sql
    assert conn.params[conn.sql.index(sql)] == (cfg.sample_threshold, cfg.retry_new_samples)


# --- mark_roles: three id-scoped UPDATEs, rest forced unused ------------------


def test_mark_roles_issues_three_scoped_updates():
    conn = FakeConn()
    split = {
        "prompt": [{"id": 1}, {"id": 2}],
        "held_out": [{"id": 3}, {"id": 4}, {"id": 5}],
        "unused": [{"id": 6}],
    }
    mark_roles(conn, split)

    # Positional pairing: the three UPDATE statements are identical strings.
    updates = [(s, p) for s, p in zip(conn.sql, conn.params)
               if isinstance(s, str) and s.startswith("UPDATE onboarding_samples")]
    assert len(updates) == 3
    assert updates[0] == (
        "UPDATE onboarding_samples SET role = %s WHERE id = ANY(%s)", ("prompt", [1, 2]))
    assert updates[1][1] == ("held_out", [3, 4, 5])
    assert updates[2][1] == ("unused", [6])
    # One txn around all three: the split lands atomically.
    assert conn.txns_opened == 1
    assert conn.sql[0] == "TXN-START" and conn.sql[-1] == "TXN-COMMIT"


def test_mark_roles_forces_unused_update_even_when_empty():
    conn = FakeConn()
    mark_roles(conn, {"prompt": [{"id": 1}], "held_out": [{"id": 2}], "unused": []})
    updates = [(s, p) for s, p in zip(conn.sql, conn.params)
               if isinstance(s, str) and s.startswith("UPDATE onboarding_samples")]
    assert len(updates) == 3
    assert updates[2][1] == ("unused", [])


# --- load_samples: ordered by (captured_at, id), role-blind, limited ----------


def test_load_samples_selects_ordered_and_limited_regardless_of_role():
    conn = FakeConn(fetchall_results=[[(7, "line a"), (3, "line b")]])
    rows = load_samples(conn, "fp_a", 20)

    assert rows == [{"id": 7, "raw_text": "line a"}, {"id": 3, "raw_text": "line b"}]
    sql = next(s for s in conn.sql if isinstance(s, str))
    assert "WHERE fingerprint_id = %s" in sql
    assert "ORDER BY captured_at, id" in sql
    assert "LIMIT %s" in sql
    assert conn.params[conn.sql.index(sql)] == ("fp_a", 20)


# --- has_active_or_pending -----------------------------------------------------


def test_has_active_or_pending_reports_both_flags():
    conn = FakeConn(fetchall_results=[[("active", 1)]])
    assert has_active_or_pending(conn, "fp_a") == (True, False)

    conn = FakeConn(fetchall_results=[[("pending_review", 2)]])
    assert has_active_or_pending(conn, "fp_a") == (False, True)

    conn = FakeConn(fetchall_results=[[]])
    assert has_active_or_pending(conn, "fp_a") == (False, False)
    sql = next(s for s in conn.sql if isinstance(s, str) and "rules" in s)
    assert "status IN ('active', 'pending_review')" in sql


# --- record_attempt + audit ----------------------------------------------------


def test_record_attempt_upserts_the_attempt_row():
    conn = FakeConn()
    record_attempt(conn, "fp_a", 20, "validation failed: boom")
    sql = next(s for s in conn.sql if isinstance(s, str))
    assert sql.startswith("INSERT INTO onboarding_attempts")
    assert "ON CONFLICT (fingerprint_id) DO UPDATE" in sql
    assert conn.params[conn.sql.index(sql)] == ("fp_a", 20, "validation failed: boom")


def test_count_samples_counts_total_for_fingerprint():
    conn = FakeConn(fetchone_results=[[45]])
    assert count_samples(conn, "fp_a") == 45
    sql = next(s for s in conn.sql if isinstance(s, str))
    assert sql == "SELECT count(*) FROM onboarding_samples WHERE fingerprint_id = %s"
    assert conn.params[conn.sql.index(sql)] == ("fp_a",)


def test_audit_inserts_row_with_actor_entity_detail():
    conn = FakeConn()
    audit(conn, "samples_split", "fp_a", {"prompt": 5, "held_out": 15, "unused": 0})
    sql = next(s for s in conn.sql if isinstance(s, str))
    assert sql == "INSERT INTO audit_log (actor, action, entity, detail) VALUES (%s, %s, %s, %s)"
    actor, action, entity, detail = (_unwrap(v) for v in conn.params[conn.sql.index(sql)])
    assert (actor, action, entity) == ("onboarding", "samples_split", "fp_a")
    assert detail == {"prompt": 5, "held_out": 15, "unused": 0}
