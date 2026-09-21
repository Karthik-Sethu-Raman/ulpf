# services/pipeline/tests/test_rules.py — active-rule cache loader pins
# (M3 R-M3-6): the per-batch SELECT must carry rules.quarantined_fields so
# the worker can filter quarantined mappings at apply time (Task 5's drift
# role appends OCSF paths there). Fake conn in the drift/onboarding house
# style — NEVER a live DB.
from ulpf_core.models import Mapping

from pipeline.rules import ActiveRule, load_active_rules


class FakeConn:
    """Fake psycopg connection: records SQL, replays scripted fetch results."""

    def __init__(self, fetchall_results=()):
        self.sql: list = []
        self._fetchall = list(fetchall_results)

    def cursor(self):
        conn = self

        class Cur:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, sql, params=None):
                conn.sql.append(sql)

            def fetchall(self):
                return conn._fetchall.pop(0)

        return Cur()


def _rule_row(rule_id=11, fp="syslog", quarantined=("src_endpoint.ip",)):
    return (rule_id, fp, 2, r"^.*?IPTABLES-\w+:\s*(?P<extension>.*)$", [
        {"source_field": "SRC", "ocsf_path": "src_endpoint.ip"},
        {"source_field": "DST", "ocsf_path": "dst_endpoint.ip"}],
        list(quarantined) if quarantined is not None else None, "human")


def test_load_active_rules_selects_quarantined_fields_column():
    conn = FakeConn([[_rule_row()]])
    rules = load_active_rules(conn)

    # Column list pinned exactly: quarantined_fields must ride the one
    # per-batch SELECT alongside mappings (TEXT[] -> Python list via psycopg).
    assert conn.sql == [
        ("SELECT id, fingerprint_id, version, pattern, mappings, "
         "quarantined_fields, provenance FROM rules WHERE status = 'active'")
    ]
    rule = rules["syslog"]
    assert isinstance(rule, ActiveRule)
    assert rule.id == 11 and rule.version == 2
    assert rule.mappings == [
        Mapping(source_field="SRC", ocsf_path="src_endpoint.ip"),
        Mapping(source_field="DST", ocsf_path="dst_endpoint.ip")]
    assert rule.quarantined_fields == ["src_endpoint.ip"]


def test_load_active_rules_null_quarantine_becomes_empty_list():
    # The column is NOT NULL DEFAULT '{}' (migration 001), but the loader is
    # defensive exactly like drift.store's: NULL -> [] so the worker's
    # falsy check (the M1/M2 hot path) still short-circuits.
    conn = FakeConn([[_rule_row(quarantined=None)]])
    assert load_active_rules(conn)["syslog"].quarantined_fields == []
